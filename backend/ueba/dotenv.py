"""Minimal ``.env`` loader with no internal dependencies.

Imported by :mod:`ueba.config` before any setting is read, so a plain
``python -m ueba`` run sees the same values systemd or Docker would inject.

Lookup order for the file: ``UEBA_ENV_FILE``, then ``<backend>/.env``, then the
repository root ``.env``.  Real environment variables always win over the file.
"""
import os
from pathlib import Path
from typing import Dict, List, Optional

# <backend>/ueba/dotenv.py -> <backend>
_BACKEND_ROOT = Path(__file__).resolve().parent.parent

_CACHE: Optional[Dict[str, str]] = None
_SOURCE: Optional[Path] = None


def candidate_paths() -> List[Path]:
    """Files we look for, in order."""
    override = os.environ.get("UEBA_ENV_FILE")
    if override:
        return [Path(override)]
    return [_BACKEND_ROOT / ".env", _BACKEND_ROOT.parent / ".env"]


def _parse(path: Path) -> Dict[str, str]:
    """Parse ``KEY=value`` lines.  Supports ``#`` comments, quoted values and a
    leading ``export``.  Malformed lines are skipped."""
    values: Dict[str, str] = {}
    try:
        text = path.read_text()
    except OSError:
        return values
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            values[key] = value
    return values


def load_dotenv(force: bool = False) -> Dict[str, str]:
    """Return the parsed ``.env`` contents (cached).  Empty when no file exists."""
    global _CACHE, _SOURCE
    if _CACHE is not None and not force:
        return _CACHE
    merged: Dict[str, str] = {}
    source: Optional[Path] = None
    for path in candidate_paths():
        if path.is_file():
            merged = _parse(path)
            source = path
            break
    _CACHE = merged
    _SOURCE = source
    return merged


def source_path() -> Optional[Path]:
    """Path of the ``.env`` that was loaded, if any."""
    load_dotenv()
    return _SOURCE


def hydrate_environment(force: bool = False) -> int:
    """Copy ``.env`` values into ``os.environ`` without overwriting existing ones.

    Returns the number of variables added.  Idempotent.
    """
    added = 0
    for key, value in load_dotenv(force=force).items():
        if key not in os.environ:
            os.environ[key] = value
            added += 1
    return added
