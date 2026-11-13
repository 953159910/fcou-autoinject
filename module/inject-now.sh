#!/system/bin/sh
# 手动注入一次（游戏已经在跑时用）
#   su -c sh /data/adb/modules/fcou_autoinject/inject-now.sh
MODDIR=${0%/*}
exec "$MODDIR/bin/fcou-inject" --once "$@"
