#!/usr/bin/env bash
# 一条命令把这个仓库推到 GitHub。
#
#   export GH_TOKEN=ghp_xxx        # Personal Access Token，勾 repo（+ workflow）权限
#   bash tools/publish.sh
#
# 可选：REPO_NAME=xxx 改仓库名，PRIVATE=1 建私有仓库，TAG=v1.1 顺便打 tag 触发 CI 发 Release。
set -euo pipefail

: "${GH_TOKEN:?请先 export GH_TOKEN=<你的 GitHub Token>}"
REPO_NAME="${REPO_NAME:-fcou-autoinject}"
PRIVATE="${PRIVATE:-0}"
API="https://api.github.com"

json_field() {  # $1=json  从 /user 里取 login
  python3 -c 'import json,sys;print(json.load(sys.stdin)["login"])' <<<"$1"
}

USER_JSON=$(curl -fsSL -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" "$API/user")
USER=$(json_field "$USER_JSON")
echo "账号: $USER"

# 建仓库（已存在就跳过）
CODE=$(curl -s -o /tmp/gh_repo.json -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
  "$API/user/repos" -d "{\"name\":\"$REPO_NAME\",\"private\":$([ "$PRIVATE" = "1" ] && echo true || echo false),\"description\":\"Minecraft 基岩版 oreUI 关闭：root 下 ptrace 自动注入 + 网页开关（Magisk/KernelSU 模块）\"}")
case "$CODE" in
  201) echo "仓库已创建 $USER/$REPO_NAME" ;;
  422) echo "仓库已存在，直接推" ;;
  *)   echo "建仓库失败 HTTP $CODE"; cat /tmp/gh_repo.json; exit 1 ;;
esac

git init -q 2>/dev/null || true
git add -A
git -c user.name="$USER" -c user.email="${GIT_EMAIL:-$USER@users.noreply.github.com}" \
    commit -q -m "fcou-autoinject: root 注入 + WebUI" || echo "没有新改动可提交"

git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$USER/$REPO_NAME.git"

# 用 token 推一次，推完把 URL 里的凭据去掉
git -c http.extraheader="Authorization: Bearer $GH_TOKEN" push -u origin HEAD:main

if [ -n "${TAG:-}" ]; then
  git tag -f "$TAG"
  git -c http.extraheader="Authorization: Bearer $GH_TOKEN" push -f origin "$TAG"
  echo "已打 tag $TAG，CI 会自动编译并发 Release"
fi

echo "完成: https://github.com/$USER/$REPO_NAME"
