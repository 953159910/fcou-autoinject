# ForceCloseOreUI Auto-Inject (with WebUI)

Root-only, no repack: **ptrace-inject `libForceCloseOreUI.so` into Minecraft Bedrock** and oreUI falls back to jsonUI.
The APK is never touched, so signature, login, worlds and store stay intact. Ships a tiny web UI with a switch.

Built on top of [yinghuajimew/ForceCloseOreUI-android](https://github.com/yinghuajimew/ForceCloseOreUI-android)
(payload) and the repack-based [No OreUI](https://github.com/yinghuajimew/yhjmew.no.ore.ui).

```sh
# install module zip from Releases, reboot, then
# open http://127.0.0.1:8899 and flip the switch (game must be running)
```

| API | |
|---|---|
| `GET /api/status` | `{pkg,pid,engine,injected,auto,port}` |
| `POST /api/inject` | run the whole inject flow, returns `{ok,log}` |
| `POST /api/auto?on=1` | toggle boot-time auto inject |

How it works: attach to the game's main thread, find an `svc #0; ret` gadget in the target libc for remote syscalls,
`mmap` a page, resolve `dlopen` by parsing the target's in-memory ELF dynsym, then `pc=dlopen / lr=0` and let the
payload's constructor do its thing. Registers are restored and the tracee is resumed with `PTRACE_CONT` — detaching
right on the `SIGSEGV` stop makes the kernel replay the faulting instruction and kills the target.

arm64 only. Payload signature table covers MC 1.21.90–1.26.60.
