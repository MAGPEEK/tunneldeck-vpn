# Sourced by build-image.sh and export-image.sh. Sets VERSION, REVISION
# and TAG (SPEC §13): VERSION is `git describe --tags --always --dirty`
# without the leading "v"; without a release tag it is
# 0.1.0-dev+<describe output>. TAG is VERSION with "+" replaced by "-",
# because Docker tags cannot contain "+".

base_version="0.1.0-dev"

describe=$(git describe --tags --always --dirty 2>/dev/null || true)
case "$describe" in
  v[0-9]*) VERSION="${describe#v}" ;;
  "") VERSION="${base_version}+unknown" ;;
  *) VERSION="${base_version}+${describe}" ;;
esac

REVISION=$(git rev-parse HEAD 2>/dev/null || echo unknown)
TAG=$(printf '%s' "$VERSION" | tr '+' '-')
IMAGE="magpeek/tunneldeck"
