#!/usr/bin/env bash
set -euo pipefail
REPO="/home/ubuntu/ARTEXSCAN/OUT/ARTEXSCAN"
BRANCH="main"
REMOTE="github.com/Zer061/ARTEXSCAN.git"
TOKEN="$(tr -d '[:space:]' < "$HOME/.config/artexscan/token")"
[ -n "$TOKEN" ] || { echo "LOI: token rong"; exit 1; }
URL="https://${TOKEN}@${REMOTE}"
mask(){ sed "s#${TOKEN}#<TOKEN>#g"; }
cd "$REPO"
git add .
git diff --cached --quiet -- out.txt || git commit -m "auto-push out.txt $(date '+%F %T')"
git pull --rebase --autostash "$URL" "$BRANCH" 2>&1 | mask || { git rebase --abort 2>/dev/null || true; exit 1; }
git push "$URL" "$BRANCH" 2>&1 | mask
echo "$(date '+%F %T') xong"
