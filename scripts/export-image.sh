#!/bin/sh
# Saves magpeek/tunneldeck-vpn:<tag> as tunneldeck-<tag>.tar in the current
# directory, for import in Synology Container Manager (Image > Add > Add
# from file).
#
#   scripts/export-image.sh [tag]
#
# The tag defaults to the version derived from git (scripts/version.sh),
# the same default as build-image.sh. Nothing is pushed.
set -eu

out_dir="$(pwd)"
cd "$(dirname "$0")/.."
. scripts/version.sh

tag="${1:-$TAG}"
output="${out_dir}/tunneldeck-${tag}.tar"

docker image inspect "${IMAGE}:${tag}" > /dev/null
docker save --output "$output" "${IMAGE}:${tag}"
echo "Wrote ${output}"
