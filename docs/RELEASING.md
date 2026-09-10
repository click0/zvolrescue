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

4. Do not create the release page by hand. The workflow creates the
   release as a **draft**, uploads every file into it, checks that the
   draft carries all of them, and only then publishes it. That order
   matters because of **release immutability** (Settings → General →
   Releases — “Disallow assets and tags from being modified once a
   release is published”): with that setting on, a published release is
   frozen, and attaching a file to it, renaming it or rewriting its
   notes is refused with a bare 403 even when the token has
   `contents: write`. A draft is still editable, so everything happens
   before the freeze. If a release for the tag already exists, the job
   tries to complete it and, if GitHub refuses, says what to do: delete
   that release (the tag can stay) and cut it again as in step 6.

6. To re-cut a release for a tag that is already pushed — a release that
   came out empty, or one made by a version of this workflow that had a
   bug — delete the release on GitHub (Releases → Edit → Delete; leave
   the tag alone) and start **Actions → Release → Run workflow** from
   `main`, giving the tag (`v0.2.0`) as the input. A tag carries the
   workflow file as it was when the tag was made, so re-running the old
   run would repeat the old behaviour; a manual run takes the workflow
   from the branch it is started on and checks out the tag for the
   source. No tag is moved, and nothing is rebuilt from different code.

7. `.github/workflows/release.yml` builds static binaries
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
