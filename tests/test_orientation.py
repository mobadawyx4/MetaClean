"""Regression tests for full-clean orientation preservation (F-03).

A full clean (``maximum`` / ``--remove all``) must strip user metadata without
changing how a viewer displays the image.  The pixel array is left untouched and
the EXIF ``Orientation`` tag is restored from the source file after ``-all=``.

Hash terminology used here:

* **File hash** covers every byte including metadata containers, so it is
  *expected* to change when metadata is removed.  It is not a visual-equality
  check.
* **Stored pixel hash** covers the decoded pixel array before any orientation
  transform.  It must be identical because a metadata-only strip must not
  re-encode pixels.
* **Displayed pixel hash** covers the pixels after applying EXIF orientation.
  It must be identical for the user-visible result to be unchanged.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from PIL import Image, ImageOps

import config
from modules.metadata_remover import MetadataRemover
from modules.metadata_scanner import MetadataScanner
from modules.metadata_verifier import MetadataVerifier, VerificationOutcome

pytestmark = pytest.mark.skipif(
    not config.EXIFTOOL_AVAILABLE,
    reason="Orientation preservation is implemented for the ExifTool cleaning path.",
)

_ORIENTATION_VALUES = list(range(1, 9))

_ORIENTATION_DISPLAY = {
    1: "Horizontal (normal)",
    2: "Mirror horizontal",
    3: "Rotate 180",
    4: "Mirror vertical",
    5: "Mirror horizontal and rotate 270 CW",
    6: "Rotate 90 CW",
    7: "Mirror horizontal and rotate 90 CW",
    8: "Rotate 270 CW",
}


def _build_asymmetric_jpeg(
    path: Path, orientation: int, *, with_private_metadata: bool = False
) -> None:
    """Creates a 40x20 JPEG whose pattern makes rotation/mirroring detectable."""
    image = Image.new("RGB", (40, 20))
    pixels = image.load()
    for y in range(20):
        for x in range(40):
            pixels[x, y] = (x * 6 % 256, y * 12 % 256, (x + y) * 4 % 256)

    exif = image.getexif()
    exif[0x0112] = orientation  # Orientation
    if with_private_metadata:
        exif[0x0131] = "TopSecretEditor 9.9"  # Software
        exif[0x013B] = "Alice Example"  # Artist
    image.save(path, "JPEG", quality=100, subsampling=0, exif=exif)


def _orientation_tag(path: Path):
    scan = MetadataScanner().scan(path)
    return next((tag for tag in scan.image_metadata.values() if tag.name == "Orientation"), None)


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _stored_hash(path: Path) -> tuple[tuple[int, int], str]:
    """Decoded pixels exactly as stored (orientation transform not applied)."""
    with Image.open(path) as image:
        image.load()
        rgb = image.convert("RGB")
        return rgb.size, hashlib.sha256(rgb.tobytes()).hexdigest()


def _displayed_hash(path: Path) -> tuple[tuple[int, int], str]:
    """Decoded pixels as a viewer displays them (EXIF orientation applied)."""
    with Image.open(path) as image:
        image.load()
        displayed = ImageOps.exif_transpose(image).convert("RGB")
        return displayed.size, hashlib.sha256(displayed.tobytes()).hexdigest()


@pytest.mark.parametrize("orientation", _ORIENTATION_VALUES)
def test_maximum_clean_preserves_display_orientation(
    orientation: int, temp_dir: Path
) -> None:
    """Every EXIF orientation value survives maximum cleaning unchanged."""
    source = temp_dir / f"orientation_{orientation}.jpg"
    cleaned = temp_dir / f"orientation_{orientation}_clean.jpg"
    _build_asymmetric_jpeg(source, orientation)

    result = MetadataRemover().clean(
        source, cleaned, profile="maximum", overwrite_output=True
    )
    assert result.success, result.errors

    tag = _orientation_tag(cleaned)
    assert tag is not None, "Orientation must survive a maximum clean"
    assert tag.display_value == _ORIENTATION_DISPLAY[orientation]

    # Stored pixels: a metadata-only strip must not re-encode the pixel array.
    assert _stored_hash(cleaned) == _stored_hash(source)
    # Displayed pixels: rotation/mirroring must look identical to the source.
    assert _displayed_hash(cleaned) == _displayed_hash(source)


def test_clean_changes_file_hash_but_not_displayed_pixels(temp_dir: Path) -> None:
    """File hashes legitimately differ after cleaning; pixel hashes must not.

    This documents why a whole-file SHA-256 is the wrong equivalence check: it
    covers stripped metadata containers.  The invariants that matter are the
    stored and displayed pixel hashes.
    """
    source = temp_dir / "orientation_6_with_metadata.jpg"
    cleaned = temp_dir / "orientation_6_with_metadata_clean.jpg"
    _build_asymmetric_jpeg(source, 6, with_private_metadata=True)

    result = MetadataRemover().clean(
        source, cleaned, profile="maximum", overwrite_output=True
    )
    assert result.success, result.errors

    assert _file_hash(cleaned) != _file_hash(source)
    assert _stored_hash(cleaned) == _stored_hash(source)
    assert _displayed_hash(cleaned) == _displayed_hash(source)


def test_maximum_clean_still_removes_unrelated_metadata(temp_dir: Path) -> None:
    """Preserving Orientation must not preserve Software/Artist or other metadata."""
    source = temp_dir / "orientation_6_private.jpg"
    cleaned = temp_dir / "orientation_6_private_clean.jpg"
    _build_asymmetric_jpeg(source, 6, with_private_metadata=True)

    result = MetadataRemover().clean(
        source, cleaned, profile="maximum", overwrite_output=True
    )
    assert result.success, result.errors

    scan = MetadataScanner().scan(cleaned)
    tag_names = {tag.name for tag in scan.image_metadata.values()}
    assert "Orientation" in tag_names
    assert "Software" not in tag_names
    assert "Artist" not in tag_names


def test_maximum_verification_accepts_preserved_orientation(temp_dir: Path) -> None:
    """Verification treats Orientation as structural, not as a residual tag."""
    source = temp_dir / "orientation_6_verify.jpg"
    cleaned = temp_dir / "orientation_6_verify_clean.jpg"
    _build_asymmetric_jpeg(source, 6)

    assert MetadataRemover().clean(
        source, cleaned, profile="maximum", overwrite_output=True
    ).success

    verification = MetadataVerifier().verify(cleaned, profile="maximum")

    assert verification.outcome == VerificationOutcome.VERIFIED_CLEAN
    assert verification.status.value == "PASS"
    assert "IFD0:Orientation" not in verification.residual_metadata_tags
