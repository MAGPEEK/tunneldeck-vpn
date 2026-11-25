#!/bin/sh
# Builds magpeek/tunneldeck-vpn:<tag> with the version from git (scripts/version.sh).
#
#   scripts/build-image.sh [tag]
#
# The tag defaults to the derived version. PLATFORM (default linux/amd64,
# the DS723+) selects the target platform. Nothing is pushed.
set -eu

cd "$(dirname "$0")/.."
. scripts/version.sh

tag="${1:-$TAG}"
platform="${PLATFORM:-linux/amd64}"

echo "Building ${IMAGE}:${tag} (version ${VERSION}, revision ${REVISION}, ${platform})"
docker build \
  --platform "$platform" \
  --build-arg VERSION="$VERSION" \
  --build-arg REVISION="$REVISION" \
  --tag "${IMAGE}:${tag}" \
  .
