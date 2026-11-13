#!/system/bin/sh
# 开机早期：只修权限（这时候游戏进程还没起来）
MODDIR=${0%/*}

chmod 755 "$MODDIR/bin/fcou-inject" 2>/dev/null
chmod 755 "$MODDIR/service.sh" "$MODDIR/inject-now.sh" "$MODDIR/webui-start.sh" 2>/dev/null
chmod 644 "$MODDIR/payload/libForceCloseOreUI.so" 2>/dev/null
chmod 755 "$MODDIR/webroot" 2>/dev/null
chmod 644 "$MODDIR/webroot/index.html" 2>/dev/null

: > "$MODDIR/fcou.log" 2>/dev/null
echo "[$(date '+%F %T')] post-fs-data: $MODDIR" >> "$MODDIR/fcou.log"
