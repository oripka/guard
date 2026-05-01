#!/bin/sh
set -eu

repo="${GUARD_REPO:-oripka/guard}"
version="${GUARD_VERSION:-latest}"
prefix="${GUARD_PREFIX:-$HOME/.local}"
install_root="${GUARD_INSTALL_ROOT:-$prefix/guard}"
bin_dir="${GUARD_BIN_DIR:-$prefix/bin}"
code_root="${GUARD_CODE_ROOT:-$HOME/code}"
force="${GUARD_FORCE:-0}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "guard installer: missing required command: $1" >&2
    exit 127
  fi
}

need curl
need tar
need uname

link_target() {
  path="$1"
  if [ -L "$path" ]; then
    readlink "$path" || printf ''
  else
    printf ''
  fi
}

is_guard_shim() {
  path="$1"
  [ -n "$path" ] || return 1
  target=$(link_target "$path")
  case "$path:$target" in
    */guard/bin/guard:*|*:*/guard/bin/guard|*/code/guard/bin/guard:*|*:*/code/guard/bin/guard)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

find_node() {
  for candidate in "${GUARD_NODE_BIN:-}" /opt/homebrew/bin/node /usr/local/bin/node /usr/bin/node "$(command -v node 2>/dev/null || true)"; do
    [ -n "$candidate" ] || continue
    [ -x "$candidate" ] || continue
    if is_guard_shim "$candidate"; then
      continue
    fi
    printf '%s\n' "$candidate"
    return 0
  done
  return 1
}

fetch() {
  if [ -n "${GH_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: Bearer $GH_TOKEN" "$@"
  else
    curl -fsSL "$@"
  fi
}

node_bin=$(find_node || true)
if [ -z "$node_bin" ]; then
  printf '%s\n' "guard installer: Node.js 20 or newer is required." >&2
  printf '%s\n' "Install Node.js first, for example: brew install node" >&2
  if is_guard_shim "$(command -v node 2>/dev/null || true)"; then
    printf '%s\n' "guard installer: found a Guard node shim on PATH; set GUARD_NODE_BIN=/absolute/path/to/node if needed." >&2
  fi
  exit 127
fi

node_major=$("$node_bin" -p "Number(process.versions.node.split('.')[0])" 2>/dev/null || printf '0')
if [ "$node_major" -lt 20 ]; then
  printf '%s\n' "guard installer: Node.js 20 or newer is required; found $("$node_bin" -v)." >&2
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

bin_guard="$bin_dir/guard"
existing_guard=$(command -v guard 2>/dev/null || true)

if [ -x "$install_root/bin/guard" ] && [ "$force" != "1" ]; then
  printf '%s\n' "guard installer: Guard already appears installed at $install_root" >&2
  printf '%s\n' "Run GUARD_FORCE=1 sh ./install.sh to replace it, or run uninstall.sh first." >&2
  exit 0
fi

if [ -e "$bin_guard" ] || [ -L "$bin_guard" ]; then
  target=$(link_target "$bin_guard")
  case "$target" in
    "$install_root"/*) ;;
    *)
      if [ "$force" != "1" ]; then
        printf '%s\n' "guard installer: $bin_guard already exists and does not point to $install_root." >&2
        printf '%s\n' "Existing target: ${target:-not a symlink}" >&2
        printf '%s\n' "This may be a source checkout or developer install. Set GUARD_FORCE=1 to replace the link." >&2
        exit 1
      fi
      ;;
  esac
fi

if [ -n "$existing_guard" ] && is_guard_shim "$existing_guard" && [ "$force" != "1" ]; then
  existing_target=$(link_target "$existing_guard")
  case "$existing_target" in
    "$install_root"/*) ;;
    *)
  printf '%s\n' "guard installer: found an existing Guard developer shim on PATH: $existing_guard" >&2
  printf '%s\n' "Keeping it unchanged. Set GUARD_FORCE=1 to install release links into $bin_dir." >&2
  exit 1
      ;;
  esac
fi

if [ "$version" = "latest" ]; then
  release_json=$(fetch "https://api.github.com/repos/$repo/releases/latest")
  version=$(printf '%s\n' "$release_json" | "$node_bin" -e 'let s=""; process.stdin.on("data", d => s += d); process.stdin.on("end", () => { const j = JSON.parse(s); process.stdout.write(j.tag_name || ""); });')
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
  asset_id=$(printf '%s\n' "$release_json" | ASSET_NAME="$asset_name" "$node_bin" -e 'let s=""; process.stdin.on("data", d => s += d); process.stdin.on("end", () => { const j = JSON.parse(s); const a = (j.assets || []).find(asset => asset.name === process.env.ASSET_NAME); process.stdout.write(a ? String(a.id) : ""); });')
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
