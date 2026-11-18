"""Safe, centralized ExifTool process backend.

All ExifTool invocations go through this module so that command construction,
argument separation, timeouts and error handling stay consistent and auditable.

Security properties:
* Argument lists are used (``shell=False`` is the default for ``subprocess.run``
  when a list is supplied); no string interpolation into a shell occurs.
* Option parsing is terminated with ``--`` before the file path, so a filename
  that begins with ``-`` cannot be interpreted as an ExifTool option.
* Absolute, resolved paths are supplied (see :func:`modules.image_validator.safe_resolve_path`).
* A hard timeout bounds resource use.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import config


@dataclass
class ExifToolResult:
    """Outcome of an ExifTool invocation."""

    ok: bool
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: Optional[str] = None

    @property
    def diagnostics(self) -> str:
        text = (self.stderr or "").strip()
        if text:
            return text
        return (self.error or "").strip()


@dataclass
class ExifToolReadResult:
    """Structured result of a metadata read."""

    ok: bool
    tags: Dict[str, Any] = field(default_factory=dict)
    raw_tags: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class ExifToolBackend:
    """Thin, defensive wrapper around the ExifTool binary."""

    def __init__(
        self,
        path: Optional[str] = None,
        version: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        if path is not None:
            self.path: Optional[str] = path
            self.version: Optional[str] = version if version is not None else config.EXIFTOOL_VERSION
            self.available = True
        else:
            self.path = config.EXIFTOOL_PATH
            self.version = config.EXIFTOOL_VERSION
            self.available = config.EXIFTOOL_AVAILABLE
        self.timeout = timeout or config.SUBPROCESS_TIMEOUT_SECONDS

    # ------------------------------------------------------------------
    # Low level invocation
    # ------------------------------------------------------------------
    def _build_command(self, args: Iterable[str], file_path: Path) -> List[str]:
        """Builds a safe argument vector terminating option parsing with ``--``."""
        if not self.path:
            raise RuntimeError("ExifTool is not available.")
        cmd: List[str] = [str(self.path)]
        # Keep non-ASCII filenames and values intact across platforms.
        cmd.extend(["-charset", "filename=UTF8"])
        cmd.extend(str(a) for a in args)
        cmd.append("--")
        cmd.append(str(file_path))
        return cmd

    def run(
        self,
        args: Sequence[str],
        file_path: str | Path,
        timeout: Optional[int] = None,
    ) -> ExifToolResult:
        """Runs ExifTool with a safe argument vector."""
        if not self.available or not self.path:
            return ExifToolResult(ok=False, error="ExifTool is not available on this system.")

        path = Path(file_path)
        cmd = self._build_command(args, path)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout or self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ExifToolResult(
                ok=False,
                timed_out=True,
                error=f"ExifTool timed out after {timeout or self.timeout}s.",
            )
        except (OSError, ValueError) as exc:
            return ExifToolResult(ok=False, error=f"Failed to execute ExifTool: {exc}")

        # ExifTool: 0 = success, 1 = minor warnings, 2 = hard error.
        ok = proc.returncode in (0, 1)
        return ExifToolResult(
            ok=ok,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )

    # ------------------------------------------------------------------
    # Metadata reading
    # ------------------------------------------------------------------
    def read_tags(
        self,
        file_path: str | Path,
        *,
        structured: bool = False,
        numeric: bool = False,
        exhaustive: bool = False,
    ) -> ExifToolReadResult:
        """Reads all tags as JSON with group names preserved.

        Args:
            file_path: Image to inspect.
            structured: Enable ``-struct`` for structured XMP/IPTC values.
            numeric: Also run a second pass with ``-n`` to capture raw values.
            exhaustive: Enable ``-ee`` to extract metadata from embedded files.
        """
        result = ExifToolReadResult(ok=False)
        args: List[str] = ["-json", "-G1", "-a", "-u"]
        if structured:
            args.append("-struct")
        if exhaustive:
            args.append("-ee")

        run = self.run(args, file_path)
        if not run.ok:
            result.errors.append(run.diagnostics or "ExifTool metadata read failed.")
            return result

        try:
            records = json.loads(run.stdout) if run.stdout.strip() else None
        except json.JSONDecodeError as exc:
            result.errors.append(f"ExifTool returned invalid JSON: {exc}")
            return result

        if not isinstance(records, list) or not records:
            result.errors.append("ExifTool returned no records for this file.")
            return result

        record = records[0]
        if not isinstance(record, dict):
            result.errors.append("ExifTool JSON record has an unexpected type.")
            return result

        result.tags = record
        result.ok = True

        # Capture ExifTool's own warnings/errors instead of treating them as tags.
        for key in list(record.keys()):
            lowered = key.lower()
            if lowered.endswith(":warning") or lowered.endswith(":error"):
                message = f"{key}: {record.pop(key)}"
                if lowered.endswith(":error"):
                    result.errors.append(message)
                else:
                    result.warnings.append(message)

        if numeric:
            raw_run = self.run(["-json", "-G1", "-a", "-u", "-n"], file_path)
            if raw_run.ok:
                try:
                    raw_records = json.loads(raw_run.stdout)
                    if isinstance(raw_records, list) and raw_records and isinstance(raw_records[0], dict):
                        result.raw_tags = raw_records[0]
                except json.JSONDecodeError:
                    result.warnings.append("Raw numeric ExifTool pass returned invalid JSON.")
            else:
                result.warnings.append("Raw numeric metadata pass failed; raw values unavailable.")

        return result

    def detect_version(self) -> Optional[str]:
        """Re-detects the installed ExifTool version (used by the ``info`` command)."""
        if not self.available or not self.path:
            return None
        result = self.run(["-ver"], ".")
        if result.ok:
            return result.stdout.strip() or None
        return None

    # ------------------------------------------------------------------
    # Metadata writing
    # ------------------------------------------------------------------
    def write(
        self,
        file_path: str | Path,
        args: Sequence[str],
        timeout: Optional[int] = None,
    ) -> ExifToolResult:
        """Applies ExifTool tag-deletion arguments in place to a working copy."""
        full_args: List[str] = list(args) + ["-overwrite_original"]
        result = self.run(full_args, file_path, timeout=timeout)
        # A zero exit code alone is not proof that anything changed. ExifTool
        # prints "N image files updated" when it rewrites the file.
        result.stdout = result.stdout or ""
        return result

    @staticmethod
    def count_updated(result: ExifToolResult) -> Optional[int]:
        """Parses ExifTool's "N image files updated" summary line, if present."""
        match = re.search(r"(\d+)\s+image files? updated", result.stdout)
        if match:
            return int(match.group(1))
        return None
