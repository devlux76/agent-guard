#!/bin/sh
set -eu
if [ "$#" != 1 ] || [ "$1" != '--deploy-reviewed' ]; then
    echo 'Usage: sh install-user.sh --deploy-reviewed (after Haiku and Opus acceptance)' >&2
    exit 2
fi
if [ "$(id -u)" = 0 ]; then echo 'Refusing a root/system-wide installation.' >&2; exit 2; fi
[ -n "${HOME:-}" ] && [ "$HOME" != '/' ] || exit 2
home=$(realpath -- "$HOME")
repo=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
prefix="$home/.local/lib/agent-guard"
link="$home/.local/bin/rm"
[ -x "$repo/build/guard-rm" ] || { echo 'Run make first.' >&2; exit 2; }

# Refuse redirects through symlinked installation or backup directories.
for dir in "$home/.local" "$home/.local/lib" "$prefix" "$prefix/bin" \
           "$prefix/libexec" "$home/.local/bin" "$home/.local/state" \
           "$home/.local/state/agent-guard" "$home/.local/state/agent-guard/backups"; do
    if [ -L "$dir" ]; then echo "Refusing symlinked install directory: $dir" >&2; exit 2; fi
done
if [ -e "$link" ] || [ -L "$link" ]; then
    if [ ! -L "$link" ] || [ "$(readlink -- "$link")" != "$prefix/bin/rm" ]; then
        echo "Refusing to overwrite your existing $link" >&2
        exit 2
    fi
fi

backup="$home/.local/state/agent-guard/backups/$(date -u +%Y%m%dT%H%M%S.%N)"
mkdir -p -- "$backup" "$prefix/bin" "$prefix/libexec" "$home/.local/bin"
chmod 700 -- "$backup"
if [ -e "$prefix/bin/rm" ]; then cp -p -- "$prefix/bin/rm" "$backup/rm.before"; fi
if [ -e "$prefix/libexec/guard-rm" ]; then
    cp -p -- "$prefix/libexec/guard-rm" "$backup/guard-rm.before"
fi
stage=$(mktemp -d "$prefix/.install.XXXXXXXX")
install -m 755 -- "$repo/build/guard-rm" "$stage/guard-rm"
install -m 755 -- "$repo/bin/rm" "$stage/rm"
mv -f -- "$stage/guard-rm" "$prefix/libexec/guard-rm"
mv -f -- "$stage/rm" "$prefix/bin/rm"
rmdir -- "$stage"
if [ ! -L "$link" ]; then ln -s -- "$prefix/bin/rm" "$link"; fi
sha256sum -- "$prefix/bin/rm" "$prefix/libexec/guard-rm" > "$backup/installed.sha256"
printf 'Installed only under %s/.local; backup: %s\n' "$home" "$backup"
echo 'Existing Bash terminals: run hash -r. New terminals and fresh agent shells see the user PATH shim.'
