#!/system/bin/sh
# 手动起 WebUI（不想等开机守护时用）
#   su -c sh /data/adb/modules/fcou_autoinject/webui-start.sh
MODDIR=${0%/*}
echo "打开 http://127.0.0.1:$(. "$MODDIR/settings.conf" 2>/dev/null; echo ${WEBUI_PORT:-8899})"
exec "$MODDIR/bin/fcou-inject" --web
