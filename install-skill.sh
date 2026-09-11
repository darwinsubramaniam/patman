#!/usr/bin/env sh
# Install the patman skill into a Claude Code harness.
#
#   ./install-skill.sh                 # personal: ~/.claude/skills/patman (symlink)
#   ./install-skill.sh --project       # this repo: ./.claude/skills/patman
#   ./install-skill.sh --project DIR   # another repo: DIR/.claude/skills/patman
#   ./install-skill.sh --copy          # copy instead of symlink (no live updates)
#   ./install-skill.sh --uninstall     # remove it again
#
# A symlink is the default so `git pull` in this checkout updates the installed
# skill. Use --copy when the checkout may move or disappear.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src="$repo/skills/patman"
scope=user
target_root=
mode=symlink
action=install

while [ $# -gt 0 ]; do
    case $1 in
        --project)
            scope=project
            case ${2-} in -*|'') ;; *) target_root=$2; shift ;; esac
            ;;
        --user)      scope=user ;;
        --copy)      mode=copy ;;
        --uninstall) action=uninstall ;;
        -h|--help)   sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)           echo "install-skill.sh: unknown option $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done

if [ "$scope" = project ]; then
    dest_dir="${target_root:-$PWD}/.claude/skills"
else
    dest_dir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}/skills"
fi
dest="$dest_dir/patman"

if [ "$action" = uninstall ]; then
    if [ -e "$dest" ] || [ -L "$dest" ]; then
        rm -rf -- "$dest"
        echo "Removed $dest"
    else
        echo "Nothing installed at $dest"
    fi
    exit 0
fi

[ -f "$src/SKILL.md" ] || { echo "install-skill.sh: no SKILL.md at $src" >&2; exit 1; }

mkdir -p -- "$dest_dir"
# Replace any previous install rather than nesting a copy inside it.
if [ -e "$dest" ] || [ -L "$dest" ]; then
    rm -rf -- "$dest"
fi

if [ "$mode" = copy ]; then
    cp -R -- "$src" "$dest"
    echo "Copied the patman skill to $dest"
else
    ln -s -- "$src" "$dest"
    echo "Linked $dest -> $src"
fi

command -v patman >/dev/null 2>&1 \
    || echo "Note: the patman binary is not on PATH. Build it with: cargo install --path $repo"
echo "Start a new Claude Code session (or run /doctor) to pick the skill up."
