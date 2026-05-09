# Release Checklist

Use this checklist before creating a GitHub release or pushing a version tag.

## Before the Merge

- Confirm the working tree is clean except for intentional release edits.
- Confirm the package version in `pyproject.toml` matches the intended tag.
- Run the full local test suite:

```bash
python -m pytest --tb=short -q
```

- Build the wheel:

```bash
python -m build --wheel
```

- Install the wheel in a clean virtual environment and verify the command paths:

```bash
python -m venv .release-venv
.release-venv\Scripts\python -m pip install --upgrade pip
.release-venv\Scripts\python -m pip install dist\chainrecon-*.whl
.release-venv\Scripts\chainrecon --help
.release-venv\Scripts\python -m chainrecon --help
python chainrecon.py --help
```

On Linux or macOS, replace `.release-venv\Scripts\...` with `.release-venv/bin/...`.

- Confirm README examples still match real commands.
- Open a pull request into `main`.
- Wait for GitHub CI to pass.
- Merge through the pull request instead of pushing directly to `main`.

## Tag and Release

- Update local `main` after the PR merge:

```bash
git checkout main
git pull --ff-only origin main
```

- Tag the final merged `main` commit. For the current package version, use:

```bash
git tag -a v1.0.0 -m "ChainRecon v1.0.0"
git push origin v1.0.0
```

- Create a GitHub release from the tag.
- In the release notes, mention:
  - package layout and install improvements
  - the current test result
  - reports are still expected to improve
  - log files are important for debugging and evidence review
  - firmware analysis is still early and will be expanded later

## Future Automation

The release is manual for now. A later GitHub Actions workflow can listen for `v*` tags, build wheels, run smoke tests, and attach artifacts to the GitHub release automatically.
