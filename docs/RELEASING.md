# Releasing

1. Update `version` in the workspace `Cargo.toml` and add a section
   `## vX.Y.Z — date` to `CHANGELOG.md` (and `CHANGELOG.uk.md`).
2. Make sure CI is green on `main`.
3. Tag and push. The tag is `vX.Y.Z` — no dot after the `v`, which is
   what the release is named and linked by:

   ```sh
   git tag -a vX.Y.Z -m "zvolrescue vX.Y.Z"
   git push origin vX.Y.Z
   ```

   A mistyped tag (`v.X.Y.Z`, `VX.Y.Z`) still releases the right version:
   the workflow normalises it for the file names and the CHANGELOG
   lookup, and warns in the job log. What it cannot fix is the tag in the
   URLs — the release page then links to a tag that does not exist. Fix
   it by deleting the tag and the release and tagging again:

   ```sh
   git tag -d v.X.Y.Z && git push origin :refs/tags/v.X.Y.Z
   # delete the release on GitHub (Releases → Edit → Delete)
   git tag -a vX.Y.Z <commit> -m "zvolrescue vX.Y.Z" && git push origin vX.Y.Z
   ```

4. If the release page already exists (created by hand), the workflow
   attaches the files to it and then refreshes the title and notes. The
   second part can be refused — a protected tag pattern (Settings → Tags)
   or immutable releases (Settings → General) both block editing a
   release even when the token has `contents: write`. The job warns and
   still leaves a complete release; the notes are then yours to paste.

5. `.github/workflows/release.yml` builds static binaries
   (`x86_64-linux-musl`, `aarch64-linux-musl`, `amd64-freebsd`), writes
   `SHA256SUMS`, takes the tag's section of `CHANGELOG.md` as the release
   notes and publishes a GitHub release — marked pre-release when the tag
   carries a suffix (`-alpha.1`, `-rc.1`).

Version numbers follow SemVer. The first cut was `v0.1.0-alpha.1`; from
then on every release is a plain minor bump — `v0.2.0`, `v0.3.0`, … — with
no pre-release suffix (a suffixed tag is still supported and is marked
pre-release on GitHub). Patch versions are for fixes to a released minor.
Until 1.0 the release notes carry the validation caveat automatically, and
[REALWORLD-TESTS.md](REALWORLD-TESTS.md) says what a release was actually
tried on. `1.0.0` waits for the real-environment matrix there.
