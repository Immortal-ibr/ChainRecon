"""Compatibility entrypoint for running ChainRecon from a source checkout."""

from chainrecon import main


if __name__ == "__main__":
    raise SystemExit(main())
