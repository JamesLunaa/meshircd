"""Allow `python -m meshircd`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
