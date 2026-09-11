# Releasing

**The tag lands on the head of `main`.** Tags here are made from the
GitHub web interface, which cannot tag an arbitrary commit — it tags a
branch, and takes its head. So the release is whatever `main` is at the
moment of tagging, and everything below follows from that:

* The version bump and the closed `## vX.Y.Z` section must be in the
  **last commit before the tag**, not in some earlier one.
* There is no tagging a milestone after the fact. A version whose commit
  has already been built on is not a release any more; it stays a
  milestone in the CHANGELOG and ships inside the next version that does
  get tagged. `v0.2.0` … `v0.7.0` went this way, and `v0.7.1` is the tag
  that carries them. The notes say so on their own: they print every
  section down to the first version that already has a release, asked of
  GitHub rather than assumed, so a deleted release puts its section back
  into the next one's notes instead of leaving it unannounced.
* Nothing lands on `main` between "CI is green" and the tag.

1. Update `version` in the workspace `Cargo.toml` and add a section
   `## vX.Y.Z — date` to `CHANGELOG.md` (and `CHANGELOG.uk.md`). Fold
   whatever `## Unreleased` holds into it: after the tag it is released,
   whether or not the section said so.
2. Make sure CI is green on `main`, and that nothing has been pushed
   since the run that went green.
3. Tag. From the web: **Releases → Draft a new release → Choose a tag →**
   type `vX.Y.Z` **→ Create new tag on publish**, target `main`, then
   publish — the tag is created on `main`'s head and the release workflow
   takes it from there. From a checkout, the same thing explicitly:

   ```sh
   git tag -a vX.Y.Z -m "zvolrescue vX.Y.Z"
   git push origin vX.Y.Z
   ```

   The tag is `vX.Y.Z` — no dot after the `v`, which is what the release
   is named and linked by.

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

   Two things in it are written by hand and have to be kept up. The
   release **title** is `zvolrescue vX.Y.Z — <the section's lead line>`,
   taken from the `**…**` that opens the CHANGELOG section, so give
   every section one. And the **Downloads** table names each program and
   what it is for; the list lives in the workflow, and the job fails if
   it does not match the binaries the build actually produced — a new
   companion tool means a new line there, not a release that ships a
   binary its own notes never mention.

   `.github/changelog-notes.py` decides which CHANGELOG sections a
   release announces. It has a self-test that the release job runs
   before it uses it.

Version numbers follow SemVer. The first cut was `v0.1.0-alpha.1`; from
then on every release is a plain minor bump — `v0.2.0`, `v0.3.0`, … — with
no pre-release suffix (a suffixed tag is still supported and is marked
pre-release on GitHub). Patch versions are for fixes to a released minor.
Until 1.0 the release notes carry the validation caveat automatically, and
[REALWORLD-TESTS.md](REALWORLD-TESTS.md) says what a release was actually
tried on. `1.0.0` waits for the real-environment matrix there.
