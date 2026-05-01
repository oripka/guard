#!/bin/sh
set -eu

prefix="${GUARD_PREFIX:-$HOME/.local}"
install_root="${GUARD_INSTALL_ROOT:-$prefix/guard}"
bin_dir="${GUARD_BIN_DIR:-$prefix/bin}"
remove_config="${GUARD_REMOVE_CONFIG:-0}"

remove_link_or_file() {
  name="$1"
  path="$bin_dir/$name"
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    return
  fi

  if [ -L "$path" ]; then
    target=$(readlink "$path" || printf '')
    case "$target" in
      "$install_root"/*|*/guard/bin/guard|*/guard/bin/iron-proxy)
        rm -f "$path"
        printf '%s\n' "Removed $path"
        ;;
      *)
        printf '%s\n' "Skipped $path; it does not point into $install_root"
        ;;
    esac
  else
    printf '%s\n' "Skipped $path; it is not a symlink"
  fi
}

for name in guard iron-proxy guard-zoom guard-teams guard-webex; do
  remove_link_or_file "$name"
done

if [ -d "$install_root" ]; then
  rm -rf "$install_root"
  printf '%s\n' "Removed $install_root"
fi

if [ "$remove_config" = "1" ]; then
  rm -rf "$HOME/.config/guard"
  printf '%s\n' "Removed $HOME/.config/guard"
else
  printf '%s\n' "Kept $HOME/.config/guard"
  printf '%s\n' "Set GUARD_REMOVE_CONFIG=1 to remove Guard config and local policy state."
fi
