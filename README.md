# ForceCloseOreUI 自动注入（带 WebUI）

[![build](../../actions/workflows/build.yml/badge.svg)](../../actions/workflows/build.yml)

有 root 就不必改包：**ptrace 把 `libForceCloseOreUI.so` 注入 Minecraft 基岩版进程**，把 oreUI 换回 jsonUI。
不改 APK、不重签名，登录态 / 存档 / 商店全不受影响。自带一个网页开关，点一下就注入。

> 基于 [yinghuajimew/ForceCloseOreUI-android](https://github.com/yinghuajimew/ForceCloseOreUI-android) 的 payload 与
> [yinghuajimew/yhjmew.no.ore.ui](https://github.com/yinghuajimew/yhjmew.no.ore.ui)（No OreUI，改包版）的思路重做：
> 那边是「改包让 so 被 `System.loadLibrary` 加载」，这里是「root 下直接塞进进程」。

---

## 它做什么

```
开机 → service.sh 起一个 WebUI（127.0.0.1:8899）
     → 你点开关（或 AUTO_INJECT=1）
     → 找 pid → 等 libminecraftpe.so 映射
     → payload 复制进 /data/data/<pkg>/files/fcou/（chown 游戏 uid + chcon app_data_file）
     → fcou-inject：PTRACE_ATTACH → 远程 mmap → 远程 dlopen(payload)
     → payload 构造函数起线程、扫特征码、DobbyHook oreUI 配置函数 → 关闭 oreUI
```

## 安装

1. 到 [Releases](../../releases) 下 `fcou_autoinject-v*.zip`；
2. Magisk / KernelSU 里「从本地安装」→ 重启；
3. 打开 **http://127.0.0.1:8899**（KernelSU 用户：模块详情 →「打开 WebUI」）；
4. **先开游戏进主菜单**，点「注入并关闭 oreUI」；
5. 想全自动，打开页面上的「开机自动注入」。

命令行等价：

```sh
su -c sh /data/adb/modules/fcou_autoinject/inject-now.sh          # 注入一次
su -c sh /data/adb/modules/fcou_autoinject/webui-start.sh          # 前台起 WebUI
su -c '/data/adb/modules/fcou_autoinject/bin/fcou-inject --status' # JSON 状态
su -c 'tail -f /data/adb/modules/fcou_autoinject/fcou.log'
su -c 'logcat -s ForceCloseOreUI'                                  # payload 日志
```

## WebUI

| 接口 | 说明 |
|---|---|
| `GET /` | 页面：三行状态 + 两个开关 + 日志 |
| `GET /api/status` | `{"pkg","pid","engine","injected","auto","port"}` |
| `POST /api/inject` | 跑完整注入流程，返回 `{"ok":true,"log":"..."}` |
| `POST /api/auto?on=1` | 改写 `settings.conf` 的 `AUTO_INJECT`（守护循环下一轮生效） |
| `GET /api/log` | `fcou.log` 尾巴 |

服务只监听 `127.0.0.1`。`webroot/index.html` 是 KernelSU 模块 WebUI 版，走 `ksu.exec` 直接执行，不依赖端口。

## 配置

`/data/adb/modules/fcou_autoinject/settings.conf`

```ini
PKG=com.mojang.minecraftpe   # 目标包名
AUTO_INJECT=0                # 1 = 开机自动注入
WEBUI_PORT=8899
RETRY=6                      # 注入重试次数
WAIT_ENGINE_S=90             # 等 libminecraftpe.so 的上限
SKIP_ENGINE_WAIT=0           # 1 = 不等引擎（调试用）
```

oreUI 逐界面开关（payload 读，改完重启游戏）：

```
/sdcard/Android/data/com.mojang.minecraftpe/mods/ForceCloseOreUI/config.json
{ "settings": false, "play": true, "achievement": false }
```

## 注入器原理

1. `PTRACE_ATTACH` 主线程，`PTRACE_GETREGSET(NT_PRSTATUS)` 存下 31 个通用寄存器 + sp/pc/pstate；
2. 在目标 `libc.so` 的 `r-x` 段里找 `svc #0; ret`（`01 00 00 D4 C0 03 5F D6`）当远程 syscall 小工具；
3. 远程 `mmap`（`__NR_mmap`=222）拿一页 RW，写入 payload 路径；
4. 在目标 `libdl.so` / `libc.so` / `linker64` 里按内存 ELF 解析出 `dlopen`（PT_DYNAMIC → DT_SYMTAB/DT_STRTAB，带 load_bias 修正）；
5. `pc = dlopen`、`lr = 0`：payload 构造函数在游戏进程里跑；返回时 `ret` 跳到 0 触发 `SIGSEGV(pc==0)`，`x0` 即返回值；
6. **恢复寄存器 → `PTRACE_CONT` 放行 → 注入器退出**（内核自动 detach）。

**踩过的坑**：不能在 `SIGSEGV` 的 signal-delivery-stop 上直接 `PTRACE_DETACH` —— 内核会重放那条缺页指令，目标当场崩。
必须先 `PTRACE_CONT` 让它跑起来，再让 tracer 退出。

## 自己编译

```sh
# 需要 aarch64 上的 musl 工具链（生成静态二进制，Android 上直接跑）
sudo apt install musl-tools
make            # 产物在 build/
make package    # 额外打出模块 zip
```

GitHub Actions 会在 push tag 时自动编译并发布 Release。

## 限制

- 只支持 **arm64**，payload 只对 `com.mojang.minecraftpe` 有意义；
- payload 签名表覆盖 MC **1.21.90 ~ 1.26.60**，游戏更新后若 `logcat -s ForceCloseOreUI` 没有 `Hook installed`，
  换新版 `third_party/libForceCloseOreUI.so` 即可，注入器不用改；
- 不要和 No OreUI 改包版同时用（同一个 so 加载两次）；
- 仅本地生效；线上服务器是否允许那是另一回事。

## 目录

```
src/fcou-inject.c       注入器 + 内置 HTTP 服务（单文件，无外部依赖）
module/                 Magisk / KernelSU 模块模板（含 service.sh，webroot 页面）
third_party/            上游 payload（版权见 NOTICE.md）
tools/package.py        打模块 zip
.github/workflows/      交叉/静态编译 + 发 Release
```

## License

本仓库代码 MIT（见 LICENSE）。`third_party/libForceCloseOreUI.so` 版权归其作者，见 NOTICE.md。
