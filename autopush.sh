#!/usr/bin/env bash
#
# auto-push.sh — commit va push cac thay doi trong repo len GitHub.
# Dung cho cron chay dinh ky (vi du moi 30 phut).
#
# Token KHONG nam trong script hay repo. Script doc token tu mot file rieng
# co quyen 600 ben ngoai repo (mac dinh ~/.config/artexscan/token).
#
# Cai dat token (chay 1 lan, thay <TOKEN> bang token cua ban):
#   mkdir -p ~/.config/artexscan && chmod 700 ~/.config/artexscan
#   printf '%s\n' '<TOKEN>' > ~/.config/artexscan/token
#   chmod 600 ~/.config/artexscan/token
#
# Cai cron moi 30 phut:
#   ( crontab -l 2>/dev/null; \
#     echo '*/30 * * * * /home/ubuntu/ARTEXSCAN/scripts/auto-push.sh >> ~/.local/share/artexscan-push.log 2>&1' \
#   ) | crontab -

set -euo pipefail

REPO="${ARTEX_REPO:-/home/ubuntu/ARTEXSCAN}"
BRANCH="${ARTEX_BRANCH:-main}"
REMOTE_HOST="${ARTEX_REMOTE:-github.com/Zer061/ARTEXSCAN.git}"
TOKEN_FILE="${ARTEX_TOKEN_FILE:-$HOME/.config/artexscan/token}"

log() { printf '%s %s\n' "$(date '+%F %T')" "$*"; }

cd "$REPO"

if [ ! -r "$TOKEN_FILE" ]; then
  log "LOI: khong doc duoc token file: $TOKEN_FILE"
  exit 1
fi
TOKEN="$(tr -d '[:space:]' < "$TOKEN_FILE")"
if [ -z "$TOKEN" ]; then
  log "LOI: token file rong: $TOKEN_FILE"
  exit 1
fi

PUSH_URL="https://${TOKEN}@${REMOTE_HOST}"
# Che URL khoi moi dong log, tranh lo token.
mask() { sed "s#${TOKEN}#<TOKEN>#g"; }

# 1) Stage moi thay doi. Neu khong co gi moi thi van thu dong bo voi remote.
git add -A
if ! git diff --cached --quiet; then
  git commit -m "auto-push $(date '+%F %T')"
  log "da commit thay doi cuc bo"
else
  log "khong co thay doi cuc bo"
fi

# 2) Keo ve va rebase de tranh bi tu choi khi remote da di truoc.
if ! git pull --rebase "$PUSH_URL" "$BRANCH" 2>&1 | mask; then
  log "LOI: rebase that bai, huy va bo qua lan nay"
  git rebase --abort 2>/dev/null || true
  exit 1
fi

# 3) Push. Push rong (khong co commit moi) la no-op, khong sao.
if git push "$PUSH_URL" "$BRANCH" 2>&1 | mask; then
  log "push xong"
else
  log "LOI: push that bai"
  exit 1
fi
