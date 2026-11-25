# Releasing

How a TunnelDeck-VPN release is cut (SPEC §13, §15). The git tag `vX.Y.Z` is the single source of truth for the version.

## Version numbers

- Semantic Versioning: stage 1 is `0.1.0`, stage 2 `0.2.0`, WireGuard `0.3.0`, `1.0.0` once data format and API are stable. While `0.y.z`, breaking changes bump the minor version and are called out in the changelog.
- Untagged builds get `0.1.0-dev+<git describe>` from `scripts/version.sh`; the image is tagged with `+` replaced by `-`.
- Image tags: `X.Y.Z`, `X.Y` and `latest` **for releases only**. Development builds use `0.1.0-dev` (or the derived dev tag); pre-releases such as `X.Y.Z-rc.1` get only their own tag.

## Before the release

1. CI is green on the release commit.
2. Full code review and security review of the whole diff since the last tag (SPEC §13).
3. For `0.1.0`: the field test on the DS723+ with the real mdex profile has passed.

## Steps

1. **Changelog.** In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and add a new, empty `## [Unreleased]` above it.
2. **Versions in files.** Set the frontend version (`npm --prefix web version X.Y.Z --no-git-tag-version`) and the `image:` tags in `docker-compose.yml`, `deploy/synology/docker-compose.yml` and the READMEs to `X.Y.Z`.
3. **Commit and tag.**

   ```sh
   git commit -am "chore(release): vX.Y.Z"
   git tag -a vX.Y.Z -m "TunnelDeck-VPN X.Y.Z"
   ```

4. **Build** from the clean, tagged tree. The script must print `version X.Y.Z` without `-dirty`.

   ```sh
   scripts/build-image.sh
   ```

5. **Smoke test** the local image:

   ```sh
   docker run -d --name td-smoke --cap-add NET_ADMIN --device /dev/net/tun \
     -e TUNNELDECK_LISTEN=0.0.0.0:8194 -p 127.0.0.1:18194:8194 magpeek/tunneldeck-vpn:X.Y.Z
   docker inspect -f '{{.State.Health.Status}}' td-smoke   # healthy after a few seconds
   docker exec td-smoke openvpn --version                  # OpenVPN 2.7.x
   ```

   Open `http://127.0.0.1:18194`, create an admin account, and check on the System page that the version is `X.Y.Z` and the self-checks pass. Run the end-to-end test (task 12). Then `docker rm -f td-smoke`.

6. **Publish** both architectures with all three tags:

   ```sh
   . scripts/version.sh
   docker buildx build --platform linux/amd64,linux/arm64 \
     --build-arg VERSION="$VERSION" --build-arg REVISION="$REVISION" \
     -t magpeek/tunneldeck-vpn:X.Y.Z -t magpeek/tunneldeck-vpn:X.Y -t magpeek/tunneldeck-vpn:latest \
     --push .
   ```

7. **Push** the commit and the tag: `git push origin main vX.Y.Z`.
8. **GitHub release** for `vX.Y.Z` with the changelog section as notes. Optionally attach `tunneldeck-X.Y.Z.tar` from `scripts/export-image.sh` for offline import in Synology Container Manager.
9. Set the compose files and READMEs back to the next development tag if work continues on `0.(Y+1).0-dev`.
