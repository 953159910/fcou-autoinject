/*
 * fcou-inject.c — aarch64 ptrace 注入器（静态编译，root 下直接在 Android 上跑）
 *
 *   fcou-inject <pid> <payload.so>
 *   fcou-inject --pkg <package> <payload.so>
 *   fcou-inject --check <pid>
 *
 * 流程：
 *   1. PTRACE_ATTACH 目标主线程，保存 31 个通用寄存器 + sp/pc/pstate
 *   2. 在目标 libc 的 r-x 段里找 "svc #0; ret"，当远程 syscall 小工具
 *   3. 远程 mmap（__NR_mmap）拿到一块 RW 内存，写入 payload 绝对路径
 *   4. 在目标模块（libdl.so / libc.so / linker64）里解析出 dlopen 地址
 *   5. PC=dlopen、LR=0 跑一次：payload 的构造函数就在目标进程里执行，
 *      dlopen 返回时 ret 掉到 0 触发 SIGSEGV(pc==0)，此时 x0 即返回值
 *   6. 恢复寄存器 → PTRACE_CONT 放行 → 注入器退出（内核自动 detach）
 *
 * 注意第 6 步：不能在 SIGSEGV stop 上直接 PTRACE_DETACH —— 内核会重放那条
 * 缺页指令，目标进程当场 SIGSEGV。必须先 CONT 让它跑起来，再让 tracer 退出。
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#ifndef __NR_mmap
#define __NR_mmap 222
#endif

typedef struct {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
} uregs_t;

#define NR_X0 0
#define NR_X8 8
#define NR_LR 30

static int g_mem = -1;
static int g_verbose = 1;
static pid_t g_pid = -1;
static uregs_t g_saved;
static int g_attached = 0;

#define LOG(...) do { if (g_verbose) { fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } } while (0)

/* ------------------------------------------------------------------ */
static int mem_open(pid_t pid) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/mem", (int)pid);
    g_mem = open(p, O_RDWR | O_CLOEXEC);
    if (g_mem < 0) LOG("open %s: %s", p, strerror(errno));
    return g_mem;
}

static int mem_read(pid_t pid, uint64_t addr, void *buf, size_t len) {
    (void)pid;
    return pread(g_mem, buf, len, (off_t)addr) == (ssize_t)len ? 0 : -1;
}

static int mem_write(pid_t pid, uint64_t addr, const void *buf, size_t len) {
    if (pwrite(g_mem, buf, len, (off_t)addr) == (ssize_t)len) return 0;
    const unsigned char *p = buf;
    for (size_t i = 0; i < len; i += 8) {
        size_t n = (len - i >= 8) ? 8 : (len - i);
        uint64_t w = 0;
        memcpy(&w, p + i, n);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)(addr + i), (void *)(uintptr_t)w) < 0)
            return -1;
    }
    return 0;
}

static int get_regs(pid_t pid, uregs_t *r) {
    struct iovec iov = { r, sizeof(*r) };
    return ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0 ? -1 : 0;
}

static int set_regs(pid_t pid, const uregs_t *r) {
    struct iovec iov = { (void *)r, sizeof(*r) };
    return ptrace(PTRACE_SETREGSET, pid, (void *)NT_PRSTATUS, &iov) < 0 ? -1 : 0;
}

/* ------------------------------------------------------------------ */
typedef struct { uint64_t start, end, off; char perms[8]; char path[512]; } mapent;

static int read_maps(pid_t pid, mapent **out, int *count) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/maps", (int)pid);
    FILE *f = fopen(p, "r");
    if (!f) { LOG("open %s: %s", p, strerror(errno)); return -1; }

    int cap = 256, n = 0;
    mapent *m = calloc(cap, sizeof(mapent));
    char line[1200];
    while (fgets(line, sizeof line, f)) {
        unsigned long long s, e, o;
        char perms[8] = {0};
        int pos = 0;
        if (sscanf(line, "%llx-%llx %7s %llx %*s %*s%n", &s, &e, perms, &o, &pos) < 4) continue;
        if (n == cap) { cap *= 2; m = realloc(m, cap * sizeof(mapent)); }
        memset(&m[n], 0, sizeof(mapent));
        m[n].start = s; m[n].end = e; m[n].off = o;
        snprintf(m[n].perms, sizeof m[n].perms, "%s", perms);
        const char *pa = line + pos;
        while (*pa == ' ') pa++;
        size_t L = strlen(pa);
        while (L && (pa[L - 1] == '\n' || pa[L - 1] == ' ')) L--;
        snprintf(m[n].path, sizeof m[n].path, "%.*s", (int)L, pa);
        n++;
    }
    fclose(f);
    *out = m; *count = n;
    return 0;
}

static int maps_contains(pid_t pid, const char *needle) {
    mapent *m = NULL; int n = 0;
    if (read_maps(pid, &m, &n) != 0) return 0;
    int hit = 0;
    for (int i = 0; i < n; i++) if (strstr(m[i].path, needle)) { hit = 1; break; }
    free(m);
    return hit;
}

static int module_range(const mapent *m, int n, const char *needle, uint64_t *base, uint64_t *span) {
    uint64_t b = 0, hi = 0;
    for (int i = 0; i < n; i++) {
        if (!strstr(m[i].path, needle)) continue;
        if (m[i].off == 0 && (b == 0 || m[i].start < b)) b = m[i].start;
        if (m[i].end > hi) hi = m[i].end;
    }
    if (!b) return -1;
    *base = b; *span = hi - b;
    return 0;
}

/* 找 "svc #0 ; ret" */
static uint64_t find_syscall_gadget(pid_t pid, const mapent *m, int n) {
    static const unsigned char pat[8] = { 0x01, 0x00, 0x00, 0xD4, 0xC0, 0x03, 0x5F, 0xD6 };
    for (int i = 0; i < n; i++) {
        if (!strstr(m[i].path, "libc.so")) continue;
        if (m[i].perms[2] != 'x') continue;
        uint64_t len = m[i].end - m[i].start;
        unsigned char *buf = malloc(len);
        if (!buf) continue;
        if (mem_read(pid, m[i].start, buf, len) != 0) { free(buf); continue; }
        uint64_t found = 0;
        for (uint64_t k = 0; k + 8 <= len; k += 4)
            if (memcmp(buf + k, pat, 8) == 0) { found = m[i].start + k; break; }
        free(buf);
        if (found) return found;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 目标进程内 ELF 符号解析                                            */
/* ------------------------------------------------------------------ */
static uint64_t sym_lookup(pid_t pid, uint64_t base, uint64_t span, const char *want) {
    Elf64_Ehdr eh;
    if (mem_read(pid, base, &eh, sizeof eh) != 0) return 0;
    if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64) return 0;

    uint64_t load_bias = base, dyn_addr = 0, dyn_size = 0;
    int have_bias = 0;
    for (int i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr ph;
        if (mem_read(pid, base + eh.e_phoff + (uint64_t)i * eh.e_phentsize, &ph, sizeof ph) != 0) return 0;
        if (ph.p_type == PT_LOAD && ph.p_offset == 0 && !have_bias) { load_bias = base - ph.p_vaddr; have_bias = 1; }
        if (ph.p_type == PT_DYNAMIC) { dyn_addr = ph.p_vaddr; dyn_size = ph.p_memsz; }
    }
    if (!dyn_addr) return 0;
    dyn_addr += load_bias;
    if (dyn_size == 0) dyn_size = 4096;

    uint64_t symtab = 0, strtab = 0, strsz = 0, hash = 0;
    for (uint64_t i = 0; i < dyn_size / 16; i++) {
        Elf64_Dyn d;
        if (mem_read(pid, dyn_addr + i * 16, &d, sizeof d) != 0) break;
        if (d.d_tag == DT_NULL) break;
        switch (d.d_tag) {
            case DT_SYMTAB: symtab = d.d_un.d_ptr; break;
            case DT_STRTAB: strtab = d.d_un.d_ptr; break;
            case DT_STRSZ:  strsz  = d.d_un.d_val; break;
            case DT_HASH:   hash   = d.d_un.d_ptr; break;
        }
    }
    if (!symtab || !strtab) return 0;

    uint64_t lo = base, hi = base + span + (1u << 24);
    if (symtab < lo || symtab > hi) symtab += load_bias;
    if (strtab < lo || strtab > hi) strtab += load_bias;
    if (hash && (hash < lo || hash > hi)) hash += load_bias;
    if (strsz == 0 || strsz > (16u << 20)) strsz = 4u << 20;

    uint64_t count = (strtab > symtab) ? (strtab - symtab) / sizeof(Elf64_Sym) : 0;
    if (count == 0 || count > 200000) count = 200000;
    if (hash) {
        uint32_t nh[2];
        if (mem_read(pid, hash, nh, sizeof nh) == 0 && nh[0] > 0 && nh[0] < 200000) count = nh[1];
    }

    size_t wantlen = strlen(want);
    Elf64_Sym batch[64];
    for (uint64_t i = 0; i < count; i += 64) {
        uint64_t k = (count - i >= 64) ? 64 : (count - i);
        if (mem_read(pid, symtab + i * sizeof(Elf64_Sym), batch, k * sizeof(Elf64_Sym)) != 0) return 0;
        for (uint64_t j = 0; j < k; j++) {
            uint32_t off = batch[j].st_name;
            if (off == 0 || off >= strsz) continue;
            char name[256];
            size_t rd = wantlen + 1 < sizeof name ? wantlen + 1 : sizeof(name) - 1;
            if (mem_read(pid, strtab + off, name, rd) != 0) continue;
            name[rd] = 0;
            if (strcmp(name, want) == 0 && batch[j].st_value) return load_bias + batch[j].st_value;
        }
    }
    return 0;
}

static uint64_t resolve_dlopen(pid_t pid, const mapent *m, int n) {
    static const char *mods[] = { "libdl.so", "libc.so", "linker64", "linker" };
    static const char *syms[] = { "dlopen", "__loader_dlopen" };
    for (size_t s = 0; s < sizeof syms / sizeof syms[0]; s++)
        for (size_t i = 0; i < sizeof mods / sizeof mods[0]; i++) {
            uint64_t base = 0, span = 0;
            if (module_range(m, n, mods[i], &base, &span) != 0) continue;
            uint64_t a = sym_lookup(pid, base, span, syms[s]);
            if (a) { LOG("%s @ 0x%llx (in %s)", syms[s], (unsigned long long)a, mods[i]); return a; }
        }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 远程调用：PC=fn，LR=0，跑到 pc==0 认为返回，x0 是返回值            */
/* ------------------------------------------------------------------ */
static int remote_call(pid_t pid, const uregs_t *base, uint64_t fn,
                       long syscall_nr, const uint64_t *args, int nargs,
                       uint64_t *out, const char *what) {
    uregs_t r = *base;
    r.pc = fn;
    r.regs[NR_LR] = 0;
    if (syscall_nr >= 0) r.regs[NR_X8] = (uint64_t)syscall_nr;
    for (int i = 0; i < nargs && i < 8; i++) r.regs[i] = args[i];
    if (set_regs(pid, &r) < 0) { LOG("[%s] SETREGSET: %s", what, strerror(errno)); return -1; }

    for (int round = 0; round < 200; round++) {
        if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) { LOG("[%s] CONT: %s", what, strerror(errno)); return -1; }
        int st = 0;
        if (waitpid(pid, &st, 0) < 0) { LOG("[%s] waitpid: %s", what, strerror(errno)); return -1; }
        if (WIFEXITED(st) || WIFSIGNALED(st)) { LOG("[%s] 目标进程退出", what); return -1; }

        uregs_t now;
        if (get_regs(pid, &now) < 0) return -1;
        if (now.pc == 0) { *out = now.regs[NR_X0]; return 0; }

        int sig = WSTOPSIG(st);
        if (sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGABRT || sig == SIGTRAP) {
            LOG("[%s] 目标异常 sig=%d pc=0x%llx", what, sig, (unsigned long long)now.pc);
            return -1;
        }
    }
    LOG("[%s] 超时", what);
    return -1;
}

/* 出错也要把目标线程放回原样 */
static void restore_and_release(pid_t pid) {
    if (!g_attached) return;
    set_regs(pid, &g_saved);
    ptrace(PTRACE_CONT, pid, 0, 0);
    g_attached = 0;
    LOG("已恢复寄存器并放行目标线程（注入器退出后内核自动 detach）");
}

/* ------------------------------------------------------------------ */
static pid_t find_pid_by_pkg(const char *pkg) {
    char cmd[128];
    snprintf(cmd, sizeof cmd, "pidof %s", pkg);
    char buf[256] = {0};
    FILE *f = popen(cmd, "r");
    if (f) { if (!fgets(buf, sizeof buf, f)) buf[0] = 0; pclose(f); }
    int pid = atoi(buf);
    if (pid > 0) return pid;
    for (int i = 1; i < 65536; i++) {
        char path[64], line[256] = {0};
        snprintf(path, sizeof path, "/proc/%d/cmdline", i);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        ssize_t r = read(fd, line, sizeof line - 1);
        close(fd);
        if (r <= 0) continue;
        if (strstr(line, pkg)) return i;
    }
    return -1;
}

static int inject(pid_t pid, const char *solib) {
    g_pid = pid;
    const char *needle = strrchr(solib, '/');
    needle = needle ? needle + 1 : solib;
    if (mem_open(pid) < 0) return 1;
    if (maps_contains(pid, needle)) { LOG("payload(%s) 已经在了，跳过", needle); return 0; }

    mapent *m = NULL; int n = 0;
    if (read_maps(pid, &m, &n) != 0) return 1;

    uint64_t gadget = find_syscall_gadget(pid, m, n);
    uint64_t dlopen_addr = resolve_dlopen(pid, m, n);
    free(m);
    if (!gadget) { LOG("目标 libc 里没有 svc 小工具，放弃"); return 1; }
    if (!dlopen_addr) { LOG("解析 dlopen 失败，放弃"); return 1; }
    LOG("svc gadget @ 0x%llx", (unsigned long long)gadget);

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) { LOG("PTRACE_ATTACH: %s", strerror(errno)); return 1; }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) { LOG("waitpid: %s", strerror(errno)); return 1; }
    g_attached = 1;
    if (get_regs(pid, &g_saved) < 0) { LOG("GETREGSET: %s", strerror(errno)); return 1; }
    LOG("目标停住 pc=0x%llx sp=0x%llx", (unsigned long long)g_saved.pc, (unsigned long long)g_saved.sp);

    int rc = 1;

    /* 1) 远程 mmap 一块 RW，用来放路径字符串 */
    uint64_t margs[6] = { 0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, (uint64_t)-1, 0 };
    uint64_t remote_mem = 0;
    if (remote_call(pid, &g_saved, gadget, __NR_mmap, margs, 6, &remote_mem, "mmap") != 0) goto out;
    if ((int64_t)remote_mem < 0 || remote_mem == 0) {
        LOG("远程 mmap 失败: 0x%llx", (unsigned long long)remote_mem);
        goto out;
    }
    LOG("远程内存 0x%llx", (unsigned long long)remote_mem);

    /* 2) 写 payload 路径 */
    if (mem_write(pid, remote_mem, solib, strlen(solib) + 1) != 0) { LOG("写路径失败"); goto out; }

    /* 3) dlopen(path, RTLD_NOW) */
    uint64_t dargs[3] = { remote_mem, 2 /*RTLD_NOW*/, 0 };
    uint64_t handle = 0;
    if (remote_call(pid, &g_saved, dlopen_addr, -1, dargs, 2, &handle, "dlopen") != 0) goto out;
    if (!handle) { LOG("dlopen 返回 NULL（路径不可读 / 依赖缺失 / payload 崩了）"); goto out; }
    LOG("dlopen 成功 handle=0x%llx", (unsigned long long)handle);

    if (maps_contains(pid, needle)) {
        LOG("注入成功：%s 已映射进目标进程", needle);
        rc = 0;
    } else {
        LOG("dlopen 成功但 maps 里没有 payload，请检查 payload 依赖");
    }

out:
    restore_and_release(pid);
    return rc;
}

/* ================================================================== */
/* WebUI：内置 HTTP 服务，127.0.0.1 上一个页面，点开关就注入           */
/* ================================================================== */
static char g_moddir[1024] = "/data/adb/modules/fcou_autoinject";
static char g_pkg[128] = "com.mojang.minecraftpe";
static int  g_auto = 0;
static int  g_port = 8899;
static int  g_retry = 6;
static int  g_wait_engine = 90;
static int  g_skip_engine_wait = 0;

static int file_exists(const char *p) { struct stat st; return stat(p, &st) == 0; }

static int looks_like_module(const char *dir) {
    char p[1200];
    snprintf(p, sizeof p, "%s/module.prop", dir);
    if (file_exists(p)) return 1;
    snprintf(p, sizeof p, "%s/payload/libForceCloseOreUI.so", dir);
    if (file_exists(p)) return 1;
    snprintf(p, sizeof p, "%s/settings.conf", dir);
    if (file_exists(p)) return 1;
    return 0;
}

/* 模块目录 = 有 module.prop / payload 的那一层。二进制在 bin/ 里，所以先往上找。 */
static void init_moddir(const char *arg0) {
    char exe[1024], dir[1024];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n > 0) {
        exe[n] = 0;
        char *s = strrchr(exe, '/');
        if (s) *s = 0;
        snprintf(dir, sizeof dir, "%s", exe);
    } else {
        const char *s = strrchr(arg0, '/');
        if (s) snprintf(dir, sizeof dir, "%.*s", (int)(s - arg0), arg0);
        else snprintf(dir, sizeof dir, ".");
    }

    for (int up = 0; up < 3; up++) {
        if (looks_like_module(dir)) break;
        char *s = strrchr(dir, '/');
        if (!s || s == dir) break;
        *s = 0;
    }
    snprintf(g_moddir, sizeof g_moddir, "%s", dir);
}

static void trim(char *s) {
    size_t L = strlen(s);
    while (L && (s[L-1] == '\n' || s[L-1] == '\r' || s[L-1] == ' ' || s[L-1] == '\t')) s[--L] = 0;
    while (*s == ' ' || *s == '\t') memmove(s, s + 1, strlen(s));
}

static void load_settings(void) {
    char p[1300];
    snprintf(p, sizeof p, "%s/settings.conf", g_moddir);
    FILE *f = fopen(p, "r");
    if (!f) return;
    char line[600];
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = line, *v = eq + 1;
        trim(k); trim(v);
        if (!strcmp(k, "PKG")) snprintf(g_pkg, sizeof g_pkg, "%s", v);
        else if (!strcmp(k, "AUTO_INJECT")) g_auto = atoi(v);
        else if (!strcmp(k, "WEBUI_PORT")) g_port = atoi(v);
        else if (!strcmp(k, "RETRY")) g_retry = atoi(v);
        else if (!strcmp(k, "WAIT_ENGINE_S")) g_wait_engine = atoi(v);
        else if (!strcmp(k, "SKIP_ENGINE_WAIT")) g_skip_engine_wait = atoi(v);
    }
    fclose(f);
    if (g_port <= 0 || g_port > 65535) g_port = 8899;
}

static void save_settings(void) {
    char p[1300], tmp[1400];
    snprintf(p, sizeof p, "%s/settings.conf", g_moddir);
    snprintf(tmp, sizeof tmp, "%s.tmp", p);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f,
        "# ForceCloseOreUI 自动注入 —— 由 WebUI 维护\n"
        "PKG=%s\n"
        "AUTO_INJECT=%d\n"
        "WEBUI_PORT=%d\n"
        "RETRY=%d\n"
        "WAIT_ENGINE_S=%d\n"
        "SKIP_ENGINE_WAIT=%d\n",
        g_pkg, g_auto, g_port, g_retry, g_wait_engine, g_skip_engine_wait);
    fclose(f);
    rename(tmp, p);
}

/* ---------- 进程 / payload 准备 ---------- */
static pid_t pkg_pid(void) {
    char cmd[200], buf[256] = {0};
    snprintf(cmd, sizeof cmd, "pidof %s", g_pkg);
    FILE *f = popen(cmd, "r");
    if (f) { if (!fgets(buf, sizeof buf, f)) buf[0] = 0; pclose(f); }
    int pid = atoi(buf);
    if (pid > 0) return pid;
    for (int i = 1; i < 65536; i++) {
        char path[64], line[512] = {0};
        snprintf(path, sizeof path, "/proc/%d/cmdline", i);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        ssize_t r = read(fd, line, sizeof line - 1);
        close(fd);
        if (r <= 0) continue;
        if (strstr(line, g_pkg)) return i;
    }
    return -1;
}

static int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY | O_CLOEXEC);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) { close(in); return -1; }
    char buf[65536];
    ssize_t n;
    int rc = 0;
    while ((n = read(in, buf, sizeof buf)) > 0)
        if (write(out, buf, n) != n) { rc = -1; break; }
    close(in); close(out);
    return rc;
}

/* 把 payload 放到游戏私有目录，并交还给游戏 uid；返回目标路径 */
static int prepare_payload(char *out, size_t outlen, char *msg, size_t msglen) {
    const char *env = getenv("FCOU_APP_LIB");
    if (env && *env) {
        snprintf(out, outlen, "%s", env);
        snprintf(msg, msglen, "使用 FCOU_APP_LIB=%s", env);
        return 0;
    }
    char appdata[300];
    struct stat st;
    snprintf(appdata, sizeof appdata, "/data/data/%s", g_pkg);
    if (stat(appdata, &st) != 0) {
        snprintf(appdata, sizeof appdata, "/data/user/0/%s", g_pkg);
        if (stat(appdata, &st) != 0) {
            snprintf(msg, msglen, "找不到 %s 的数据目录", g_pkg);
            return -1;
        }
    }
    char dir[360];
    snprintf(dir, sizeof dir, "%s/files/fcou", appdata);
    mkdir(dir, 0700);
    snprintf(out, outlen, "%s/libForceCloseOreUI.so", dir);

    char src[1300];
    snprintf(src, sizeof src, "%s/payload/libForceCloseOreUI.so", g_moddir);
    if (copy_file(src, out) != 0) {
        snprintf(msg, msglen, "复制 payload 失败: %s → %s", src, out);
        return -1;
    }
    if (chown(dir, st.st_uid, st.st_gid) != 0) { /* 忽略 */ }
    if (chown(out, st.st_uid, st.st_gid) != 0) { /* 忽略 */ }
    chmod(dir, 0700);
    chmod(out, 0600);
    char cmd[900];
    snprintf(cmd, sizeof cmd, "chcon -R u:object_r:app_data_file:s0 '%s' 2>/dev/null", dir);
    if (system(cmd) != 0) { /* 没有 chcon 就算了，多数 ROM 会自动继承 */ }
    snprintf(msg, msglen, "payload 就位: %s", out);
    return 0;
}

/* 一次完整的“找进程 → 等引擎 → 准备 → 注入”，日志写 fd */
static int do_inject_flow(int logfd) {
    dprintf(logfd, "target: %s\n", g_pkg);
    pid_t pid = pkg_pid();
    if (pid <= 0) { dprintf(logfd, "游戏没在跑（%s）\n", g_pkg); return 1; }
    dprintf(logfd, "pid: %d\n", (int)pid);

    const char *skip = getenv("FCOU_SKIP_ENGINE_WAIT");
    if (skip && *skip == '1') g_skip_engine_wait = 1;

    int waited = 0;
    while (!g_skip_engine_wait && waited < g_wait_engine) {
        if (maps_contains(pid, "libminecraftpe.so")) break;
        struct timespec ts = { 1, 0 };
        nanosleep(&ts, NULL);
        waited++;
        if (waited % 10 == 0) dprintf(logfd, "等引擎加载 … %ds\n", waited);
    }
    if (!g_skip_engine_wait && !maps_contains(pid, "libminecraftpe.so")) {
        dprintf(logfd, "等了 %ds 还没看到 libminecraftpe.so\n", waited);
        return 1;
    }
    if (!g_skip_engine_wait) dprintf(logfd, "引擎已加载（%ds）\n", waited);
    else dprintf(logfd, "已跳过引擎等待（SKIP_ENGINE_WAIT=1）\n");

    if (maps_contains(pid, "libForceCloseOreUI.so")) {
        dprintf(logfd, "payload 已经在进程里，无需重复注入\n");
        return 0;
    }

    char lib[1300], msg[2800];
    if (prepare_payload(lib, sizeof lib, msg, sizeof msg) != 0) {
        dprintf(logfd, "%s\n", msg);
        return 1;
    }
    dprintf(logfd, "%s\n", msg);

    for (int i = 1; i <= g_retry; i++) {
        dprintf(logfd, "第 %d 次注入 …\n", i);
        int rc = inject(pid, lib);
        if (rc == 0 || maps_contains(pid, "libForceCloseOreUI.so")) {
            dprintf(logfd, "注入成功\n");
            return 0;
        }
        if (kill(pid, 0) != 0) { dprintf(logfd, "目标进程已经退出\n"); return 1; }
        sleep(2);
    }
    dprintf(logfd, "注入失败（%d 次）\n", g_retry);
    return 1;
}

/* ---------- HTTP ---------- */
static void http_send(int fd, int code, const char *ctype, const char *body, size_t len) {
    char head[256];
    int n = snprintf(head, sizeof head,
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
        "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        code, code == 200 ? "OK" : "Bad Request", ctype, len);
    if (write(fd, head, n) < 0) return;
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, body + off, len - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
}

static void json_escape(const char *in, char *out, size_t outlen) {
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 8 < outlen; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c == '\n') { out[o++] = '\\'; out[o++] = 'n'; }
        else if (c == '\r') { out[o++] = '\\'; out[o++] = 'r'; }
        else if (c == '\t') { out[o++] = '\\'; out[o++] = 't'; }
        else if (c < 0x20) { out[o++] = ' '; }
        else out[o++] = (char)c;
    }
    out[o] = 0;
}

static const char *html_page(void) {
    static const char *page =
"<!doctype html><html lang=zh><head><meta charset=utf-8>"
"<meta name=viewport content=width=device-width,initial-scale=1>"
"<title>ForceCloseOreUI</title><style>"
"body{margin:0;padding:18px;background:#0e1014;color:#e8eaf0;font-family:system-ui,sans-serif}"
".card{max-width:520px;margin:0 auto;background:#171a21;border:1px solid #242833;border-radius:16px;padding:18px}"
"h1{font-size:18px;margin:0 0 14px;letter-spacing:.5px}"
".row{display:flex;justify-content:space-between;font-size:14px;padding:7px 0;color:#9aa3b2}"
".row b{color:#e8eaf0;font-weight:600}"
".sw{display:flex;align-items:center;gap:12px;margin:16px 0;cursor:pointer}"
".sw input{display:none}"
".sl{width:52px;height:30px;border-radius:16px;background:#333a47;position:relative;flex:0 0 auto;transition:.18s}"
".sl:after{content:'';position:absolute;top:4px;left:4px;width:22px;height:22px;border-radius:50%;background:#8b94a6;transition:.18s}"
".sw input:checked+.sl{background:#2f6bff}"
".sw input:checked+.sl:after{left:26px;background:#fff}"
".sw em{font-style:normal;font-size:15px}"
"pre{background:#0b0d11;border:1px solid #242833;border-radius:10px;padding:10px;font-size:12px;"
"line-height:1.45;max-height:220px;overflow:auto;white-space:pre-wrap;color:#9fe0b0;margin:12px 0 0}"
"small{color:#6d7686;font-size:12px;display:block;margin-top:10px;line-height:1.5}"
"</style></head><body><div class=card><h1>ForceCloseOreUI</h1>"
"<div class=row><span>游戏进程</span><b id=pid>-</b></div>"
"<div class=row><span>引擎 libminecraftpe</span><b id=eng>-</b></div>"
"<div class=row><span>payload</span><b id=inj>-</b></div>"
"<label class=sw><input type=checkbox id=tg><span class=sl></span><em>注入并关闭 oreUI</em></label>"
"<label class=sw><input type=checkbox id=au><span class=sl></span><em>开机自动注入</em></label>"
"<pre id=log>点上面的开关开始</pre>"
"<small>先开游戏、进到主菜单再点。开关只能开不能关：注入是进程级的，想恢复就重启游戏。</small>"
"</div><script>"
"const $=id=>document.getElementById(id);"
"async function refresh(){try{const r=await fetch('/api/status',{cache:'no-store'});const j=await r.json();"
"$('pid').textContent=j.pid>0?('PID '+j.pid):'未运行';"
"$('eng').textContent=j.engine?'已加载':'未加载';"
"$('inj').textContent=j.injected?'已注入':'未注入';"
"$('tg').checked=j.injected;$('au').checked=j.auto===1;}catch(e){$('pid').textContent='服务未连接';}}"
"$('tg').addEventListener('change',async e=>{if(!e.target.checked){e.target.checked=true;return;}"
"$('log').textContent='注入中，别切走 …';"
"try{const r=await fetch('/api/inject',{method:'POST'});const j=await r.json();"
"$('log').textContent=j.log+(j.ok?' [成功]':' [失败]');}catch(err){$('log').textContent='请求失败: '+err;}"
"refresh();});"
"$('au').addEventListener('change',async e=>{"
"await fetch('/api/auto?on='+(e.target.checked?1:0),{method:'POST'});refresh();});"
"refresh();setInterval(refresh,2500);"
"</script></body></html>";
    return page;
}

static void handle_client(int cfd) {
    char req[4096];
    ssize_t n = read(cfd, req, sizeof req - 1);
    if (n <= 0) { close(cfd); return; }
    req[n] = 0;

    char method[8] = {0}, path[512] = {0};
    if (sscanf(req, "%7s %511s", method, path) != 2) { close(cfd); return; }
    char *q = strchr(path, '?');
    char query[256] = {0};
    if (q) { snprintf(query, sizeof query, "%s", q + 1); *q = 0; }

    if (!strcmp(path, "/") || !strcmp(path, "/index.html")) {
        const char *page = html_page();
        http_send(cfd, 200, "text/html; charset=utf-8", page, strlen(page));
    } else if (!strcmp(path, "/api/status")) {
        pid_t pid = pkg_pid();
        int engine = 0, injected = 0;
        if (pid > 0) {
            engine = maps_contains(pid, "libminecraftpe.so");
            injected = maps_contains(pid, "libForceCloseOreUI.so");
        }
        char body[512];
        int len = snprintf(body, sizeof body,
            "{\"pkg\":\"%s\",\"pid\":%d,\"engine\":%s,\"injected\":%s,\"auto\":%d,\"port\":%d}",
            g_pkg, (int)(pid > 0 ? pid : 0), engine ? "true" : "false",
            injected ? "true" : "false", g_auto, g_port);
        http_send(cfd, 200, "application/json", body, (size_t)len);
    } else if (!strcmp(path, "/api/auto")) {
        int on = 0;
        char *p = strstr(query, "on=");
        if (p) on = atoi(p + 3);
        g_auto = on ? 1 : 0;
        save_settings();
        char body[96];
        int len = snprintf(body, sizeof body, "{\"ok\":true,\"auto\":%d}", g_auto);
        http_send(cfd, 200, "application/json", body, (size_t)len);
    } else if (!strcmp(path, "/api/log")) {
        char lp[1300];
        snprintf(lp, sizeof lp, "%s/fcou.log", g_moddir);
        FILE *f = fopen(lp, "r");
        char buf[8192] = {0};
        size_t got = 0;
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            long from = sz > 4000 ? sz - 4000 : 0;
            fseek(f, from, SEEK_SET);
            got = fread(buf, 1, sizeof buf - 1, f);
            buf[got] = 0;
            fclose(f);
        }
        http_send(cfd, 200, "text/plain; charset=utf-8", buf, strlen(buf));
    } else if (!strcmp(path, "/api/inject")) {
        /* 子进程里跑注入，父进程带超时收集日志 */
        int pfd[2];
        if (pipe(pfd) != 0) { close(cfd); return; }
        pid_t child = fork();
        if (child == 0) {
            close(pfd[0]);
            dup2(pfd[1], 1);
            dup2(pfd[1], 2);
            close(pfd[1]);
            _exit(do_inject_flow(1) == 0 ? 0 : 1);
        }
        close(pfd[1]);
        char log[6144];
        size_t used = 0;
        time_t deadline = time(NULL) + 120;
        for (;;) {
            struct pollfd pf = { pfd[0], POLLIN, 0 };
            int pr = poll(&pf, 1, 1000);
            if (pr > 0) {
                ssize_t r = read(pfd[0], log + used, sizeof log - 1 - used);
                if (r > 0) { used += (size_t)r; if (used >= sizeof log - 1) break; continue; }
                if (r == 0) break;
            }
            if (time(NULL) > deadline) break;
        }
        log[used] = 0;
        close(pfd[0]);
        int status = 0;
        waitpid(child, &status, 0);

        int ok = (WIFEXITED(status) && WEXITSTATUS(status) == 0);
        char esc[8192];
        json_escape(log, esc, sizeof esc);
        char *body = malloc(strlen(esc) + 128);
        int len = snprintf(body, strlen(esc) + 128,
            "{\"ok\":%s,\"log\":\"%s\"}", ok ? "true" : "false", esc);
        http_send(cfd, 200, "application/json", body, (size_t)len);
        free(body);
    } else {
        http_send(cfd, 400, "text/plain", "not found", 9);
    }
    close(cfd);
}

static int serve_forever(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)g_port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0) {
        fprintf(stderr, "bind 127.0.0.1:%d 失败: %s\n", g_port, strerror(errno));
        return 1;
    }
    listen(s, 8);
    fprintf(stderr, "WebUI: http://127.0.0.1:%d  (模块目录 %s)\n", g_port, g_moddir);
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; break; }
        struct timeval tv = { 10, 0 };
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        handle_client(c);
    }
    close(s);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "用法:\n"
            "  %s <pid> <payload.so>\n"
            "  %s --pkg <package> <payload.so>\n"
            "  %s --check <pid>\n"
            "  %s --web [port]       # 启动 WebUI\n"
            "  %s --once [pkg]       # 命令行跑一次完整注入\n"
            "  %s --status           # 打印一段 JSON 状态\n",
            argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "--web") == 0) {
        init_moddir(argv[0]);
        load_settings();
        if (argc >= 3 && atoi(argv[2]) > 0) g_port = atoi(argv[2]);
        return serve_forever();
    }
    if (strcmp(argv[1], "--once") == 0) {
        init_moddir(argv[0]);
        load_settings();
        if (argc >= 3) snprintf(g_pkg, sizeof g_pkg, "%s", argv[2]);
        return do_inject_flow(1) == 0 ? 0 : 1;
    }
    if (strcmp(argv[1], "--status") == 0) {
        init_moddir(argv[0]);
        load_settings();
        pid_t p = pkg_pid();
        printf("{\"pkg\":\"%s\",\"pid\":%d,\"engine\":%s,\"injected\":%s,\"auto\":%d}\n",
               g_pkg, (int)(p > 0 ? p : 0),
               (p > 0 && maps_contains(p, "libminecraftpe.so")) ? "true" : "false",
               (p > 0 && maps_contains(p, "libForceCloseOreUI.so")) ? "true" : "false",
               g_auto);
        return 0;
    }
    if (strcmp(argv[1], "--check") == 0) {
        pid_t pid = (pid_t)atoi(argv[2]);
        if (pid <= 0) return 2;
        if (mem_open(pid) < 0) return 1;
        mapent *m = NULL; int n = 0;
        if (read_maps(pid, &m, &n) != 0) return 1;
        printf("pid=%d\n", pid);
        printf("minecraft engine: %s\n", maps_contains(pid, "libminecraftpe.so") ? "loaded" : "not loaded");
        printf("payload loaded  : %s\n", maps_contains(pid, "libForceCloseOreUI.so") ? "yes" : "no");
        printf("syscall gadget  : 0x%llx\n", (unsigned long long)find_syscall_gadget(pid, m, n));
        printf("dlopen          : 0x%llx\n", (unsigned long long)resolve_dlopen(pid, m, n));
        return 0;
    }

    if (strcmp(argv[1], "--pkg") == 0) {
        if (argc < 4) return 2;
        pid_t pid = find_pid_by_pkg(argv[2]);
        if (pid <= 0) { fprintf(stderr, "进程没在跑: %s\n", argv[2]); return 1; }
        LOG("找到进程 %s -> %d", argv[2], (int)pid);
        return inject(pid, argv[3]);
    }

    pid_t pid = (pid_t)atoi(argv[1]);
    if (pid <= 0) return 2;
    return inject(pid, argv[2]);
}
