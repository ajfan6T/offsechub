import sys

from .cli import main

if __name__ == "__main__":  # also imported by multiprocessing children
    sys.exit(main())
