# Releasing

Releases are driven by a version tag. You push a tag, and GitHub Actions
does the rest: it publishes the gem, pushes the Docker image to Docker Hub
and GHCR, and creates the GitHub Release.

## One-time setup

Done once, in the repo on GitHub. Settings, then Secrets and variables,
then Actions.

Add these repository secrets:

| Secret              | Where it comes from                                   |
|---------------------|-------------------------------------------------------|
| `RUBYGEMS_API_KEY`  | rubygems.org, your profile, API keys. Scope it to push. |
| `DOCKERHUB_USERNAME`| your Docker Hub username                              |
| `DOCKERHUB_TOKEN`   | Docker Hub, Account Settings, Security, new access token |

Also, before the first publish, confirm you own the gem name
`datalink-socket` on rubygems.org. If someone else holds it, change
`spec.name` in the gemspec and the image name in the workflow.

GHCR needs no setup. The workflow signs in with the built-in Actions
token.

## Cutting a release

1. Bump the version in `lib/datalink/version.rb`.
2. Add a section to `CHANGELOG.md` for the new version. Use the same
   header shape as the existing entries, for example
   `## 1.1.0 (2026-11-02)`. The release notes are pulled from this
   section, so write it for a reader.
3. Commit both on a branch, open a PR, and merge it.
4. Tag the merge commit and push the tag:

   ```sh
   git checkout master && git pull
   git tag -a v1.1.0 -m "datalink-socket 1.1.0"
   git push origin v1.1.0
   ```

That tag push triggers the release workflow.

## What the tag triggers

The `Release` workflow (`.github/workflows/release.yml`) runs three jobs:

- **test**: the full suite, as a gate. Nothing publishes if it fails.
- **gem**: checks the tag matches `version.rb`, builds the gem, pushes it
  to RubyGems, and creates the GitHub Release with notes taken from the
  CHANGELOG section for this version. The built `.gem` is attached to the
  Release.
- **docker**: builds the image and pushes it to both
  `docker.io/<your-user>/datalink-socket` and
  `ghcr.io/jeanmichel-gh/datalink-socket`, tagged with the full version,
  the major.minor, and `latest`.

## Notes

- The tag version and the gem version must match, or the gem job fails on
  purpose. Bump `version.rb` before tagging.
- Release notes live only in the GitHub Release and `CHANGELOG.md`. Do not
  commit a `RELEASE_NOTES` file; `.gitignore` keeps them out.
- `Gemfile.lock` is not committed. A library is tested across the Ruby
  matrix in CI, so it is not pinned.
- The Docker image ships the `arp-scan` and `arp-spoof` CLIs. Raw layer 2
  from a container needs `--net=host --cap-add=NET_RAW`, and even then is
  limited by the container's network.

## Local alternative

If you ever need to publish by hand from your machine, with your own
credentials:

```sh
gem build datalink-socket.gemspec
gem push datalink-socket-<version>.gem
```

The CI path above is the normal route.
