"""Project Metadata based on its ``pyproject.toml``."""

from __future__ import annotations

import importlib.metadata

__all__ = ("__project__", "__version__")

__version__ = importlib.metadata.version("litestar-api-auth")
"""Version of the project."""
__project__ = importlib.metadata.metadata("litestar-api-auth")["Name"]
"""Name of the project."""
