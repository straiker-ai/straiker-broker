#!/usr/bin/env bash
# Regenerate the guard's OpenShell supervisor-middleware stubs (pkg/guard/openshell/pb) from a pinned OpenShell
# commit, with a pinned protoc and pinned Go plugins, so the committed code is reproducible: run it and
# `git diff --exit-code` shows nothing.
#
#   scripts/openshell-proto.sh          (needs curl, unzip and Go; linux or macOS, amd64 or arm64)
#
# The protos are vendored verbatim in third_party/openshell/proto. They are compiled as openshell/<name>.proto
# so their descriptor paths (openshell/extension.proto) cannot collide with another module's bare
# extension.proto in the process-wide protobuf registry.
set -euo pipefail

TAG="v0.1.6" # v0.1.7 carries the same middleware protocol
COMMIT="ac7f615cd12d5cc49cb16eb1f5f10ffeb1e90f47"
PROTOS=(extension supervisor_middleware)
PROTOC_VERSION="36.2"
PROTOC_GEN_GO="google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12"
PROTOC_GEN_GO_GRPC="google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.2"
MODULE="github.com/straiker-ai/straiker-broker"
OUT_PKG="pkg/guard/openshell/pb"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)          platform=linux-x86_64;   sum=121f6c7afe1d4d0e3ea6aab9432038599250134cbf4474cb1167d2c7decd4278 ;;
  Linux-aarch64)         platform=linux-aarch_64; sum=8b8f18bd2b30346efbc698dd5a73dd7c805f3ef8380f6dfc95c768f3f1852f6a ;;
  Darwin-arm64)          platform=osx-aarch_64;   sum=9cd98a532c5c5e0c4161314de0225de27e4c8a323917b6ea7b1b714d3ae23466 ;;
  Darwin-x86_64)         platform=osx-x86_64;     sum=228cc7add4616cc14ca5e80dee83209d44449a7aee95a914ae748fa374efb078 ;;
  *) echo "openshell-proto.sh: no pinned protoc for $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

zip="$work/protoc.zip"
curl -fsSL "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-${platform}.zip" -o "$zip"
if command -v sha256sum >/dev/null; then got=$(sha256sum "$zip"); else got=$(shasum -a 256 "$zip"); fi
[ "${got%% *}" = "$sum" ] || { echo "openshell-proto.sh: protoc checksum mismatch: ${got%% *}" >&2; exit 1; }
unzip -q "$zip" -d "$work/protoc"

GOBIN="$work/bin" go install "$PROTOC_GEN_GO"
GOBIN="$work/bin" go install "$PROTOC_GEN_GO_GRPC"

mkdir -p "$work/src/openshell" "$root/third_party/openshell/proto"
opts=()
files=()
for p in "${PROTOS[@]}"; do
  curl -fsSL "https://raw.githubusercontent.com/NVIDIA/OpenShell/${COMMIT}/proto/${p}.proto" \
    -o "$root/third_party/openshell/proto/${p}.proto"
  sed -E 's#^import "([a-z_]+)\.proto";#import "openshell/\1.proto";#' \
    "$root/third_party/openshell/proto/${p}.proto" >"$work/src/openshell/${p}.proto"
  files+=("openshell/${p}.proto")
  pkg="${p//_/}v1"
  pkg="${pkg/supervisormiddleware/middleware}"
  opts+=("--go_opt=Mopenshell/${p}.proto=${MODULE}/${OUT_PKG}/${pkg};${pkg}")
  opts+=("--go-grpc_opt=Mopenshell/${p}.proto=${MODULE}/${OUT_PKG}/${pkg};${pkg}")
done

rm -rf "${root:?}/${OUT_PKG}"
mkdir -p "$work/gen"
PATH="$work/bin:$PATH" "$work/protoc/bin/protoc" -I "$work/src" -I "$work/protoc/include" \
  --go_out="$work/gen" --go_opt=module="$MODULE" \
  --go-grpc_out="$work/gen" --go-grpc_opt=module="$MODULE" \
  "${opts[@]}" "${files[@]}"
mkdir -p "$root/${OUT_PKG}"
cp -R "$work/gen/${OUT_PKG}/." "$root/${OUT_PKG}/"
printf 'OpenShell %s (%s); protoc %s, %s, %s\n' "$TAG" "$COMMIT" "$PROTOC_VERSION" "$PROTOC_GEN_GO" "$PROTOC_GEN_GO_GRPC" \
  >"$root/${OUT_PKG}/VERSION"
