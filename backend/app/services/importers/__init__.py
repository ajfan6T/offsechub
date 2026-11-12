"""Importers for tool output. ``parsers.PARSERS`` maps each tool to its parser."""

# Load the registry first: burp.py and nessus.py build on its classes and it
# registers them, so this keeps every import order working.
from . import parsers  # noqa: F401
