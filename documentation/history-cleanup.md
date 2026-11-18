# Public history cleanup runbook (not executed)

The 2.0 tree removes private lab defaults and a tracked `.coverage` database. It does not remove past Git objects or change the online repository. No history rewrite, force push, or GitHub setting change is part of this release preparation.

## Local audit already performed

`git ls-files` showed the tracked `.coverage` file, `config/local.yaml`, a device profile, a workflow, three device-specific Frida scripts, and a live-test helper. `git log --all --` confirms that private lab paths appeared in historical commits including `58eac58` and `98d4586`. The working tree removes those files. A user-local backup was placed under `%APPDATA%\ChainRecon\private-archive-20261117` before local removal. Do not upload that archive.

## Before a separately authorized history rewrite

1. Identify every sensitive path and any actual credentials or tokens in all refs, tags, pull-request refs, release assets, and forks. Use local `git log --all --name-only`, `git grep` against selected historic commits, and a secret scanner; record findings without copying secret values into issues or logs.
2. Revoke or rotate any exposed credential, even if a later history rewrite is planned.
3. Coordinate a maintenance window and notify collaborators that a force-pushed history will require a fresh clone or careful reset. Back up the full repository and map all protected branches and tags.
4. In a disposable mirror clone, use `git filter-repo --invert-paths --path <path>` (or an approved equivalent) for the confirmed path list. Review the rewritten history and test source and wheel builds there.
5. Only after explicit authorization, push rewritten refs, address repository-side cached references and pull-request artifacts using GitHub's sensitive-data removal process, and ask fork owners to remove their copies. A history rewrite cannot erase independent clones or screenshots.
6. Re-run secret scanning, check public refs, and document remaining exposure.

Do not run the rewrite directly in this working checkout. Keep the path list and credential review private until the cleanup is coordinated.
