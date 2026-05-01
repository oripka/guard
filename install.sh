#!/bin/sh
set -eu

repo="${GUARD_REPO:-oripka/guard}"
version="${GUARD_VERSION:-latest}"
prefix="${GUARD_PREFIX:-$HOME/.local}"
install_root="${GUARD_INSTALL_ROOT:-$prefix/guard}"
bin_dir="${GUARD_BIN_DIR:-$prefix/bin}"
code_root="${GUARD_CODE_ROOT:-$HOME/code}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "guard installer: missing required command: $1" >&2
    exit 127
  fi
}

need curl
need tar
need uname

fetch() {
  if [ -n "${GH_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: Bearer $GH_TOKEN" "$@"
  else
    curl -fsSL "$@"
  fi
}

if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' "guard installer: Node.js 20 or newer is required." >&2
  printf '%s\n' "Install Node.js first, for example: brew install node" >&2
  exit 127
fi

node_major=$(node -p "Number(process.versions.node.split('.')[0])" 2>/dev/null || printf '0')
if [ "$node_major" -lt 20 ]; then
  printf '%s\n' "guard installer: Node.js 20 or newer is required; found $(node -v)." >&2
  exit 1
fi

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Darwin) platform=darwin ;;
  Linux) platform=linux ;;
  *)
    printf '%s\n' "guard installer: unsupported OS: $os" >&2
    exit 1
    ;;
esac

case "$arch" in
  arm64|aarch64) cpu=arm64 ;;
  x86_64|amd64) cpu=x64 ;;
  *)
    printf '%s\n' "guard installer: unsupported CPU architecture: $arch" >&2
    exit 1
    ;;
esac

if [ "$platform" = "linux" ]; then
  printf '%s\n' "guard installer: Linux support is experimental; macOS is the supported alpha platform." >&2
fi

if [ "$version" = "latest" ]; then
  release_json=$(fetch "https://api.github.com/repos/$repo/releases/latest")
  version=$(printf '%s\n' "$release_json" | node -e 'let s=""; process.stdin.on("data", d => s += d); process.stdin.on("end", () => { const j = JSON.parse(s); process.stdout.write(j.tag_name || ""); });')
  if [ -z "$version" ]; then
    printf '%s\n' "guard installer: could not resolve latest release for $repo" >&2
    exit 1
  fi
else
  release_json=$(fetch "https://api.github.com/repos/$repo/releases/tags/$version")
fi

asset_name="guard-cli-${version#v}-$platform-$cpu.tar.gz"
release_url="https://github.com/$repo/releases/download/$version/$asset_name"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/guard-install.XXXXXX")
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT HUP INT TERM

archive="$tmp_dir/guard-cli.tar.gz"

printf '%s\n' "Downloading Guard CLI from $release_url"
if [ -n "${GH_TOKEN:-}" ]; then
  asset_id=$(printf '%s\n' "$release_json" | ASSET_NAME="$asset_name" node -e 'let s=""; process.stdin.on("data", d => s += d); process.stdin.on("end", () => { const j = JSON.parse(s); const a = (j.assets || []).find(asset => asset.name === process.env.ASSET_NAME); process.stdout.write(a ? String(a.id) : ""); });')
  if [ -z "$asset_id" ]; then
    printf '%s\n' "guard installer: could not find release asset: $asset_name" >&2
    exit 1
  fi
  curl -fL \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/octet-stream" \
    "https://api.github.com/repos/$repo/releases/assets/$asset_id" \
    -o "$archive"
else
  fetch "$release_url" -o "$archive"
fi

rm -rf "$install_root"
mkdir -p "$install_root" "$bin_dir"
tar -xzf "$archive" -C "$install_root" --strip-components=1

if [ ! -x "$install_root/bin/guard" ]; then
  printf '%s\n' "guard installer: archive did not contain bin/guard" >&2
  exit 1
fi

ln -sfn "$install_root/bin/guard" "$bin_dir/guard"
if [ -x "$install_root/bin/iron-proxy" ]; then
  ln -sfn "$install_root/bin/iron-proxy" "$bin_dir/iron-proxy"
fi

"$install_root/bin/guard" setup --yes --bin-dir "$bin_dir" --code-root "$code_root" --force --no-shims

printf '%s\n' "Guard installed into $install_root"
printf '%s\n' "Linked guard into $bin_dir"
case ":${PATH:-}:" in
  *":$bin_dir:"*) ;;
  *)
    printf '%s\n' "Add this to your shell profile if needed:"
    printf '%s\n' "  export PATH=\"$bin_dir:\$PATH\""
    ;;
esac
