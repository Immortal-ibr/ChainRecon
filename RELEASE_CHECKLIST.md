# ChainRecon 2.0 release checklist

The release branch contains version `2.0.0`. Keep the tag on the final merged
`main` commit so the source archive, wheel metadata, and recorded run version
agree. Publishing and pushing are manual.

## Local gates

Run from the repository root:

```powershell
python -m pip check
python -m pip_audit . --strict
python -m ruff check chainrecon tests scripts --select E4,E7,E9,F
python -m pytest tests --cov=chainrecon --cov-branch --cov-report=xml:coverage.xml
python -m coverage json -o coverage.json
python scripts/check_coverage.py coverage.json
python scripts/build_clean.py --outdir dist
python scripts/check_dist.py
python scripts/smoke_install.py 'dist/chainrecon-2.0.0-*.whl'
python scripts/smoke_install.py 'dist/chainrecon-2.0.0.tar.gz'
```

Also run the scoped mypy command from `.github/workflows/ci.yml` and confirm
`git diff --check` is clean before committing.

The full offline suite should have one intentional skip: the Frida test that
requires a configured Android emulator and server. It runs separately with
`CHAINRECON_LIVE_FRIDA=1` on a prepared local bench. The offline Frida command
tests must run in CI.

Review the wheel and source archive for required bundled assets, license, and
private material. The release artifact must not contain local settings, case
folders, firmware, packet captures, or device-specific research files.

## Publish the source branch

Push the prepared `release/v2.0.0` branch and open a pull request into `main`.
Wait for every GitHub Actions job to pass on Windows and Linux with Python
3.11–3.13, plus the package smoke and dependency audit jobs. Do not tag a
branch whose hosted checks have not passed.

## Tag after the merge

```powershell
git switch main
git pull --ff-only origin main
git tag -a v2.0.0 -m "ChainRecon 2.0.0"
git push origin v2.0.0
```

Create the GitHub release from `v2.0.0` and attach the tested wheel and source
archive only if they were rebuilt from that exact tagged commit. Note the one
optional live Frida check and the absence of a C210 physical-device validation.

The v2 tree removes prior private lab defaults and examples. Public Git history
still contains older device-specific research files. A history rewrite is a
separate coordinated action; see `documentation/history-cleanup.md`.
