"""PyInstaller entry point (the console script is app.cli:main)."""

import multiprocessing
import sys

from app.cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
