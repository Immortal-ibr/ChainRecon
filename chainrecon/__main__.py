"""Allow ``python -m chainrecon`` to run the CLI."""

from chainrecon import main


if __name__ == "__main__":
    raise SystemExit(main())
