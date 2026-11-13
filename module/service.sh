#!/system/bin/sh
# =====================================================================
# ForceCloseOreUI 自动注入 —— Magisk / KernelSU 的 late_start service
#
#   · 常驻一个 WebUI（默认 http://127.0.0.1:8899），点开关就注入
#   · AUTO_INJECT=1 时，开机自动注入（关掉就只靠手动）
#   真正的注入逻辑都在 bin/fcou-inject 里，这里只负责拉起和守护。
# =====================================================================
MODDIR=${0%/*}
LOGF="$MODDIR/fcou.log"
WEBLOG="$MODDIR/webui.log"
BIN="$MODDIR/bin/fcou-inject"

log() { echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOGF"; }

rotate_log() {
    [ -f "$LOGF" ] || return 0
    if [ "$(wc -c < "$LOGF" 2>/dev/null || echo 0)" -gt 262144 ]; then
        tail -n 200 "$LOGF" > "$LOGF.tmp" 2>/dev/null && mv -f "$LOGF.tmp" "$LOGF"
    fi
}

start_webui() {
    if [ -f "$MODDIR/webui.pid" ]; then
        old=$(cat "$MODDIR/webui.pid" 2>/dev/null)
        if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
            return 0
        fi
    fi
    if command -v setsid >/dev/null 2>&1; then
        setsid "$BIN" --web >> "$WEBLOG" 2>&1 &
    else
        nohup "$BIN" --web >> "$WEBLOG" 2>&1 &
    fi
    echo $! > "$MODDIR/webui.pid"
    log "WebUI 启动 pid=$! port=${WEBUI_PORT:-8899}"
}

# 等系统起来
i=0
while [ "$i" -lt 120 ]; do
    [ "$(getprop sys.boot_completed 2>/dev/null)" = "1" ] && break
    sleep 2
    i=$((i + 1))
done
sleep 2
rotate_log
log "=== 守护启动 ==="

while true; do
    [ -f "$MODDIR/settings.conf" ] && . "$MODDIR/settings.conf"
    start_webui

    if [ "${AUTO_INJECT:-0}" = "1" ]; then
        # 自动模式：进程在跑、还没注入时自动来一发；其余情况 --once 会自己跳过
        "$BIN" --once >> "$LOGF" 2>&1
        sleep 10
    else
        sleep 20
    fi
    rotate_log
done
