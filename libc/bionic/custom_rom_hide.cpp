/*
 * Copyright (C) 2025-2026 AxionOS
 * Copyright (C) 2026 VoltageOS
 * Copyright (C) 2026 crDroid Android Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "custom_rom_hide.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/memfd.h>
#include <linux/stat.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/system_properties.h>
#include <sys/uio.h>
#include <unistd.h>
#include <private/android_filesystem_config.h>
#include <private/bionic_lock.h>

#define HIDE_MEMFD_TAG "mf"
#define HIDE_MEMFD_NAME_PREFIX HIDE_MEMFD_TAG ":"
#define HIDE_MEMFD_LINK_PREFIX "/memfd:" HIDE_MEMFD_TAG ":"
#define HIDE_MEMFD_LINK_PREFIX_LEN (sizeof(HIDE_MEMFD_LINK_PREFIX) - 1)
#define HIDE_TRACKED_FD_LIMIT 32768
#define HIDE_TRACKED_FD_WORD_BITS 64
#define HIDE_TRACKED_FD_WORD_COUNT (HIDE_TRACKED_FD_LIMIT / HIDE_TRACKED_FD_WORD_BITS)

#ifndef OVERLAYFS_SUPER_MAGIC
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#endif
#ifndef EROFS_SUPER_MAGIC_V1
#define EROFS_SUPER_MAGIC_V1 0xe0f5e1e2
#endif
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC 0x01021994
#endif

struct PrefixEntry {
    const char* str;
    size_t len;
};
#define PE(s) { s, sizeof(s) - 1 }

static const char* const kBlockedDirnames[] = {
    "addon.d", "init.d", "TWRP", nullptr
};

static const PrefixEntry kDirParents[] = {
    PE("/system"), PE("/system/etc"),
    PE("/system_ext"), PE("/system_ext/etc"),
    PE("/product"), PE("/product/etc"),
    PE("/vendor"), PE("/vendor/etc"),
    PE("/odm"), PE("/odm/etc"),
    PE("/etc"),
    PE("/sdcard"), PE("/data/media/0"),
    { nullptr, 0 }
};

static const PrefixEntry kFrameworkDirs[] = {
    PE("/system/framework"),
    PE("/system_ext/framework"),
    PE("/product/framework"),
    { nullptr, 0 }
};

static const PrefixEntry kOverlayDirs[] = {
    PE("/system/overlay"),
    PE("/system_ext/overlay"),
    PE("/product/overlay"),
    PE("/vendor/overlay"),
    PE("/odm/overlay"),
    { nullptr, 0 }
};

static const PrefixEntry kRomArtifactPrefixes[] = {
    PE("org.evolution."),
    PE("org.lineageos."),
    PE("org.libremobileos."),
    PE("com.crdroid."),
    PE("lineage-sdk"),
    PE("lineagesettings"),
    PE("co.aospa."),
    PE("com.android.axion."),
    PE("org.lunaris."),
    PE("org.omnirom."),
    PE("org.protonaosp."),
    { nullptr, 0 }
};

static const PrefixEntry kProcFilterKeywords[] = {
    PE("lineage"), PE("Lineage"), PE("evolution"), PE("Evolution"),
    PE("omnirom"), PE("aospa"),
    { nullptr, 0 }
};

static const PrefixEntry kConfigDirs[] = {
    PE("/system/etc/selinux"),      PE("/system_ext/etc/selinux"),
    PE("/product/etc/selinux"),     PE("/vendor/etc/selinux"),
    PE("/odm/etc/selinux"),
    PE("/system/etc/init"),         PE("/system_ext/etc/init"),
    PE("/product/etc/init"),        PE("/vendor/etc/init"),
    PE("/odm/etc/init"),
    PE("/system/etc/permissions"),  PE("/system_ext/etc/permissions"),
    PE("/product/etc/permissions"), PE("/vendor/etc/permissions"),
    PE("/odm/etc/permissions"),
    PE("/system/etc/sysconfig"),    PE("/system_ext/etc/sysconfig"),
    PE("/product/etc/sysconfig"),   PE("/vendor/etc/sysconfig"),
    PE("/odm/etc/sysconfig"),
    PE("/system/etc/vintf"),        PE("/system_ext/etc/vintf"),
    PE("/product/etc/vintf"),       PE("/vendor/etc/vintf"),
    PE("/odm/etc/vintf"),
    { nullptr, 0 }
};

static const char* const kMountFilterKeywords[] = {
    "/debug_ramdisk", "overlay", "magisk", "ksu", "KSU", "ksud", "apatch", "/data/adb", nullptr
};

static const char* const kAllowlistedPackages[] = {
    "org.lineageos.updater",
    nullptr
};

#define DM_MAJOR 253u

struct PartitionDevEntry {
    const char* path;
    unsigned int dm_minor;
};

static const PartitionDevEntry kPartitionDmMap[] = {
    { "/system",            0 },
    { "/vendor",            1 },
    { "/product",           2 },
    { "/system_ext",        3 },
    { "/odm",               4 },
    { "/system/vendor",     1 },
    { "/system/product",    2 },
    { "/system/system_ext", 3 },
    { "/system/odm",        4 },
    { nullptr,              0 },
};

static _Atomic(uint64_t) g_substituted_fd_bits[HIDE_TRACKED_FD_WORD_COUNT];

static bool is_trackable_fd(int fd) {
    return fd >= 0 && fd < HIDE_TRACKED_FD_LIMIT;
}

static bool is_tracked_fd(int fd) {
    if (!is_trackable_fd(fd)) return false;
    uint64_t bit = 1ULL << (fd % HIDE_TRACKED_FD_WORD_BITS);
    uint64_t word = atomic_load_explicit(&g_substituted_fd_bits[fd / HIDE_TRACKED_FD_WORD_BITS],
                                         memory_order_acquire);
    return (word & bit) != 0;
}

static void register_fd(int fd) {
    if (!is_trackable_fd(fd)) return;
    uint64_t bit = 1ULL << (fd % HIDE_TRACKED_FD_WORD_BITS);
    atomic_fetch_or_explicit(&g_substituted_fd_bits[fd / HIDE_TRACKED_FD_WORD_BITS], bit,
                             memory_order_release);
}

// Metadata of the real file, captured when the substitution is created while the
// canonical path still resolves. It is the fallback for fstat/statx once that path
// no longer resolves — a file opened through /proc/thread-self by a thread that has
// exited, or a substituted file of another process that has gone. Indexed by fd,
// parallel to g_substituted_fd_bits.
//
// g_fd_meta_lock guards both the pointers and the lifetime of the records: a reader
// copies the record out under the lock, so a concurrent store/clear that frees the
// old record (e.g. dup2 over an fd another thread is stat-ing) cannot free it while
// the reader still dereferences it.
struct FdMeta {
    struct stat sb;
    struct statx sx;
    bool sb_ok;
    bool sx_ok;
};

static constexpr unsigned kStatxCaptureMask = STATX_ALL | STATX_DIOALIGN |
        STATX_MNT_ID_UNIQUE | STATX_SUBVOL | STATX_WRITE_ATOMIC | STATX_DIO_READ_ALIGN;

static FdMeta* g_fd_meta[HIDE_TRACKED_FD_LIMIT];
static Lock g_fd_meta_lock;
static pthread_once_t g_fd_meta_atfork_once = PTHREAD_ONCE_INIT;

static void prepare_fd_meta_fork() { g_fd_meta_lock.lock(); }
static void parent_fd_meta_fork() { g_fd_meta_lock.unlock(); }
static void child_fd_meta_fork() { g_fd_meta_lock.init(false); }

static void register_fd_meta_atfork() {
    pthread_atfork(prepare_fd_meta_fork, parent_fd_meta_fork, child_fd_meta_fork);
}

static void clear_fd_meta(int fd) {
    if (!is_trackable_fd(fd)) return;
    g_fd_meta_lock.lock();
    FdMeta* prev = g_fd_meta[fd];
    g_fd_meta[fd] = nullptr;
    g_fd_meta_lock.unlock();
    free(prev);
}

static void store_fd_meta(int fd, const FdMeta* meta) {
    if (!is_trackable_fd(fd)) return;
    FdMeta* copy = static_cast<FdMeta*>(malloc(sizeof(FdMeta)));
    if (!copy) {
        clear_fd_meta(fd);
        return;
    }
    *copy = *meta;
    g_fd_meta_lock.lock();
    FdMeta* prev = g_fd_meta[fd];
    g_fd_meta[fd] = copy;
    g_fd_meta_lock.unlock();
    free(prev);
}

static bool load_fd_meta(int fd, FdMeta* out) {
    if (!is_trackable_fd(fd)) return false;
    bool ok = false;
    g_fd_meta_lock.lock();
    if (g_fd_meta[fd]) { *out = *g_fd_meta[fd]; ok = true; }
    g_fd_meta_lock.unlock();
    return ok;
}

void custom_rom_hide_unregister_fd(int fd) {
    if (!is_trackable_fd(fd)) return;
    uint64_t bit = 1ULL << (fd % HIDE_TRACKED_FD_WORD_BITS);
    _Atomic(uint64_t)* word = &g_substituted_fd_bits[fd / HIDE_TRACKED_FD_WORD_BITS];
    // close() routes here for every fd; an untracked one must not touch the meta lock.
    if ((atomic_load_explicit(word, memory_order_acquire) & bit) == 0) return;
    atomic_fetch_and_explicit(word, ~bit, memory_order_release);
    clear_fd_meta(fd);
}

void custom_rom_hide_transfer_fd(int old_fd, int new_fd) {
    if (new_fd < 0 || old_fd == new_fd) return;
    if (is_tracked_fd(old_fd)) {
        FdMeta meta;
        if (load_fd_meta(old_fd, &meta)) store_fd_meta(new_fd, &meta);
        else clear_fd_meta(new_fd);
        register_fd(new_fd);
    } else {
        custom_rom_hide_unregister_fd(new_fd);
    }
}

static inline int raw_openat(const char* path, int flags) {
    return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, flags, 0));
}

static inline ssize_t raw_read(int fd, void* buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

static inline ssize_t raw_write(int fd, const void* buf, size_t count) {
    return syscall(__NR_write, fd, buf, count);
}

static inline int raw_close(int fd) {
    return static_cast<int>(syscall(__NR_close, fd));
}

static inline off_t raw_lseek(int fd, off_t offset, int whence) {
    return syscall(__NR_lseek, fd, offset, whence);
}

static inline int raw_memfd_create(const char* name, unsigned int flags) {
    return static_cast<int>(syscall(__NR_memfd_create, name, flags));
}

static inline ssize_t raw_readlinkat(const char* path, char* buf, size_t size) {
    return syscall(__NR_readlinkat, AT_FDCWD, path, buf, size);
}

static bool read_cwd_path(char* buf, size_t size) {
    if (!buf || size < 2) return false;
    int saved_errno = errno;
    ssize_t n = raw_readlinkat("/proc/self/cwd", buf, size - 1);
    if (n > 0 && static_cast<size_t>(n) < size) {
        buf[n] = '\0';
        errno = saved_errno;
        return true;
    }
    errno = saved_errno;
    return false;
}

static inline int raw_fstatat(int dirfd, const char* path, struct stat* sb, int flags) {
#if defined(__LP64__)
    return static_cast<int>(syscall(__NR_newfstatat, dirfd, path, sb, flags));
#else
    return static_cast<int>(syscall(__NR_fstatat64, dirfd, path, sb, flags));
#endif
}

static inline int raw_statx(int dirfd, const char* path, int flags, unsigned mask, struct statx* sx) {
    return static_cast<int>(syscall(__NR_statx, dirfd, path, flags, mask, sx));
}

static inline int raw_statfs(const char* path, struct statfs* sf) {
#if defined(__LP64__)
    return static_cast<int>(syscall(__NR_statfs, path, sf));
#else
    return static_cast<int>(syscall(__NR_statfs64, path, sizeof(*sf), sf));
#endif
}

static bool read_cmdline_name(char* out, size_t out_size) {
    if (out_size == 0) return false;
    int fd = raw_openat("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return false;

    ssize_t n = raw_read(fd, out, out_size - 1);
    raw_close(fd);
    if (n <= 0) return false;

    out[n] = '\0';
    if (char* colon = strchr(out, ':')) *colon = '\0';
    return true;
}

static bool name_is_zygote(const char* name) {
    if (strcmp(name, "app_process") == 0 || strcmp(name, "app_process64") == 0 ||
        strcmp(name, "app_process32") == 0) return true;
    size_t len = strlen(name);
    static const char kZygoteSuffix[] = "_zygote";
    size_t slen = sizeof(kZygoteSuffix) - 1;
    if (len >= slen && strcmp(name + len - slen, kZygoteSuffix) == 0) return true;
    if (strcmp(name, "zygote") == 0 || strcmp(name, "zygote64") == 0) return true;
    if (strcmp(name, "usap32") == 0 || strcmp(name, "usap64") == 0) return true;
    return false;
}

static bool compute_exempt(bool* is_zygote) {
    *is_zygote = false;

    char name[256];
    if (!read_cmdline_name(name, sizeof(name)) || name[0] == '\0') {
        *is_zygote = true;
        return true;
    }

    if (name_is_zygote(name)) { *is_zygote = true; return true; }

    for (const char* const* p = kAllowlistedPackages; *p; ++p) {
        if (strcmp(name, *p) == 0) return true;
    }
    return false;
}

static bool is_exempt_process() {
    static _Atomic(pid_t) cached_pid = -1;
    static _Atomic(bool) cached_value = false;
    pid_t cur = getpid();
    if (atomic_load_explicit(&cached_pid, memory_order_acquire) == cur) {
        return atomic_load_explicit(&cached_value, memory_order_relaxed);
    }

    bool is_zygote = false;
    bool result = compute_exempt(&is_zygote);
    if (!is_zygote) {
        atomic_store_explicit(&cached_value, result, memory_order_relaxed);
        atomic_store_explicit(&cached_pid, cur, memory_order_release);
    }
    return result;
}

static bool is_app_process() {
    if ((getuid() % AID_USER_OFFSET) < AID_APP_START) return false;
    if (is_exempt_process()) return false;
    return true;
}

// Dynamic prop overrides are only meant for DroidGuard, mirroring PIFork's scope.
// The process name is only final once ActivityThread has called Process.setArgV0(),
// before that cmdline still reads "zygote*" or "<pre-initialized>". Only cache
// once it is final so an early read can't pin the wrong answer for this pid.
#define DROIDGUARD_PROCESS_NAME "com.google.android.gms.unstable"

static bool compute_droidguard(bool* resolved) {
    *resolved = false;

    int fd = raw_openat("/proc/self/cmdline", O_RDONLY);
    if (fd < 0) return false;

    char cmdline[256];
    ssize_t n = raw_read(fd, cmdline, sizeof(cmdline) - 1);
    raw_close(fd);
    if (n <= 0) return false;

    cmdline[n] = '\0';
    if (strncmp(cmdline, "zygote", 6) == 0 || strcmp(cmdline, "<pre-initialized>") == 0) {
        return false;
    }

    *resolved = true;
    return strcmp(cmdline, DROIDGUARD_PROCESS_NAME) == 0;
}

static bool is_droidguard_process() {
    static _Atomic(pid_t) cached_pid = -1;
    static _Atomic(bool) cached_value = false;

    pid_t cur = getpid();
    if (atomic_load_explicit(&cached_pid, memory_order_acquire) == cur) {
        return atomic_load_explicit(&cached_value, memory_order_acquire);
    }

    bool resolved = false;
    bool result = compute_droidguard(&resolved);
    if (resolved) {
        atomic_store_explicit(&cached_value, result, memory_order_release);
        atomic_store_explicit(&cached_pid, cur, memory_order_release);
    }
    return result;
}

static const char* path_basename(const char* path) {
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static bool path_parent_equals(const char* path, const char* parent, size_t plen) {
    if (strncmp(path, parent, plen) != 0) return false;
    return path[plen] == '/';
}

static bool basename_is_rom_artifact(const char* name) {
    for (const PrefixEntry* p = kRomArtifactPrefixes; p->str; ++p) {
        if (strncmp(name, p->str, p->len) == 0) return true;
    }
    return false;
}

static bool name_has_rom_keyword(const char* name) {
    for (const PrefixEntry* kw = kProcFilterKeywords; kw->str; ++kw) {
        if (strstr(name, kw->str) != nullptr) return true;
    }
    return false;
}

static bool dir_is_config(const char* dir_path) {
    for (const PrefixEntry* d = kConfigDirs; d->str; ++d) {
        if (strcmp(dir_path, d->str) == 0) return true;
    }
    return false;
}

static bool is_rom_framework_artifact(const char* path) {
    const char* rest = nullptr;
    for (const PrefixEntry* d = kFrameworkDirs; d->str; ++d) {
        if (strncmp(path, d->str, d->len) == 0 && path[d->len] == '/') {
            rest = path + d->len + 1;
            break;
        }
    }
    if (!rest) return false;
    const char* slash = strrchr(rest, '/');
    return basename_is_rom_artifact(slash ? slash + 1 : rest);
}

static bool is_rom_overlay(const char* path) {
    const char* rest = nullptr;
    for (const PrefixEntry* d = kOverlayDirs; d->str; ++d) {
        if (strncmp(path, d->str, d->len) == 0 && path[d->len] == '/') {
            rest = path + d->len + 1;
            break;
        }
    }
    if (!rest) return false;
    const char* slash = strrchr(rest, '/');
    const char* base = slash ? slash + 1 : rest;
    return basename_is_rom_artifact(base) || name_has_rom_keyword(base);
}

static bool is_blocked_dir(const char* path) {
    const char* base = path_basename(path);

    bool name_match = false;
    for (const char* const* dn = kBlockedDirnames; *dn; ++dn) {
        if (strcmp(base, *dn) == 0) { name_match = true; break; }
    }
    if (!name_match) return false;

    for (const PrefixEntry* pp = kDirParents; pp->str; ++pp) {
        if (path_parent_equals(path, pp->str, pp->len)) return true;
    }
    return false;
}

static bool normalize_absolute_path(const char* path, char* out, size_t out_size) {
    if (!path || path[0] != '/' || !out || out_size < 2) return false;

    size_t out_len = 0;
    out[out_len++] = '/';
    const char* p = path;
    while (*p) {
        while (*p == '/') ++p;
        if (!*p) break;

        const char* segment = p;
        while (*p && *p != '/') ++p;
        size_t segment_len = static_cast<size_t>(p - segment);

        if (segment_len == 1 && segment[0] == '.') continue;
        if (segment_len == 2 && segment[0] == '.' && segment[1] == '.') {
            while (out_len > 1 && out[out_len - 1] != '/') --out_len;
            if (out_len > 1) --out_len;
            continue;
        }

        if (out_len > 1) {
            if (out_len + 1 >= out_size) return false;
            out[out_len++] = '/';
        }
        if (out_len + segment_len >= out_size) return false;
        memcpy(out + out_len, segment, segment_len);
        out_len += segment_len;
    }

    out[out_len] = '\0';
    return true;
}

static bool path_is_config_artifact(const char* path) {
    if (!path) return false;

    for (const PrefixEntry* d = kConfigDirs; d->str; ++d) {
        if (strncmp(path, d->str, d->len) != 0 || path[d->len] != '/') continue;

        const char* rest = path + d->len + 1;
        while (*rest) {
            const char* slash = strchr(rest, '/');
            size_t component_len = slash ? static_cast<size_t>(slash - rest) : strlen(rest);
            if (component_len >= 512) return false;

            char component[512];
            memcpy(component, rest, component_len);
            component[component_len] = '\0';
            if (name_has_rom_keyword(component) || basename_is_rom_artifact(component)) {
                return true;
            }
            if (!slash) break;
            rest = slash + 1;
        }
    }
    return false;
}

static bool path_may_be_config_path(const char* path) {
    if (!path) return false;
    if (strstr(path, "etc/") != nullptr) return true;
    for (const PrefixEntry* kw = kProcFilterKeywords; kw->str; ++kw) {
        if (strstr(path, kw->str) != nullptr) return true;
    }
    for (const char* const* dn = kBlockedDirnames; *dn; ++dn) {
        if (strstr(path, *dn) != nullptr) return true;
    }
    return false;
}

static bool path_is_in_blocked_dir(const char* path) {
    bool candidate = false;
    for (const char* const* dn = kBlockedDirnames; *dn; ++dn) {
        if (strstr(path, *dn) != nullptr) { candidate = true; break; }
    }
    if (!candidate) return false;

    char prefix[512];
    size_t len = 0;
    const char* p = path;
    while (*p) {
        while (*p == '/') ++p;
        if (!*p) break;

        const char* segment = p;
        while (*p && *p != '/') ++p;
        size_t segment_len = static_cast<size_t>(p - segment);
        if (len + 1 + segment_len >= sizeof(prefix)) return false;

        prefix[len++] = '/';
        memcpy(prefix + len, segment, segment_len);
        len += segment_len;
        prefix[len] = '\0';
        if (is_blocked_dir(prefix)) return true;
    }
    return false;
}

static bool is_rom_path(const char* path) {
    if (!path || path[0] != '/') return false;

    char normalized[512];
    if (!normalize_absolute_path(path, normalized, sizeof(normalized))) return false;

    if (is_blocked_dir(normalized)) return true;
    if (path_is_in_blocked_dir(normalized)) return true;
    if (is_rom_framework_artifact(normalized)) return true;
    if (path_is_config_artifact(normalized)) return true;
    return false;
}

static bool resolve_fd_path(int fd, char* buf, size_t size) {
    char proc_link[64];
    if (fd < 0 || !buf || size < 2) return false;
    snprintf(proc_link, sizeof(proc_link), "/proc/self/fd/%d", fd);
    ssize_t n = raw_readlinkat(proc_link, buf, size - 1);
    if (n > 0) {
        buf[n] = '\0';
        return true;
    }
    return false;
}

static ssize_t safe_copy_string(const char* addr, char* buf, size_t size) {
    if (!addr || size == 0) return -1;

    int saved_errno = errno;
    ssize_t result = -1;

    size_t page = static_cast<size_t>(getpagesize());
    if (page == 0) page = 4096;

    size_t len = 0;
    const size_t max = size - 1;

    while (len < max) {
        uintptr_t cur = reinterpret_cast<uintptr_t>(addr) + len;
        size_t chunk = page - (cur % page);
        if (chunk > max - len) chunk = max - len;

        struct iovec local = { buf + len, chunk };
        struct iovec remote = {
            reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(addr) + len), chunk };
        ssize_t n = syscall(__NR_process_vm_readv, getpid(), &local, 1, &remote, 1, 0);
        if (n < 0) goto out;

        char* nul = static_cast<char*>(memchr(buf + len, '\0', static_cast<size_t>(n)));
        if (nul) {
            result = static_cast<ssize_t>(nul - buf);
            goto out;
        }

        len += static_cast<size_t>(n);
        if (static_cast<size_t>(n) < chunk) {
            goto out;
        }
    }
out:
    errno = saved_errno;
    return result;
}

static bool resolve_path_at(int dirfd, const char* path, char* out, size_t out_size) {
    char local[512];
    if (safe_copy_string(path, local, sizeof(local)) < 0) return false;
    if (local[0] == '/') return normalize_absolute_path(local, out, out_size);

    char dir_path[512];
    bool have_dir = dirfd == AT_FDCWD
            ? read_cwd_path(dir_path, sizeof(dir_path))
            : resolve_fd_path(dirfd, dir_path, sizeof(dir_path));
    if (!have_dir) return false;

    char full_path[1024];
    int n = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, local);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(full_path)) return false;
    return normalize_absolute_path(full_path, out, out_size);
}

bool custom_rom_hide_resolve_path(int dirfd, const char* path, char* out, size_t out_size) {
    return resolve_path_at(dirfd, path, out, out_size);
}

static bool proc_fd_alias_is_hidden(const char* path) {
    if (!path) return false;
    int saved_errno = errno;
    char target[512];
    bool hidden = custom_rom_hide_resolve_proc_fd_path(path, target, sizeof(target)) &&
                  is_rom_path(target);
    errno = saved_errno;
    return hidden;
}

bool custom_rom_hide_should_block(const char* path) {
    if (!path || reinterpret_cast<uintptr_t>(path) < 0x1000000) return false;
    if (!is_app_process()) return false;

    char local[512];
    if (safe_copy_string(path, local, sizeof(local)) < 0) return false;
    if (proc_fd_alias_is_hidden(local)) return true;
    if (local[0] == '/') return is_rom_path(local);

    const char* base = path_basename(local);
    size_t local_len = strlen(local);
    bool candidate = local_len > 0 && local[local_len - 1] == '/';
    for (const char* const* dn = kBlockedDirnames; !candidate && *dn; ++dn) {
        if (strcmp(base, *dn) == 0) { candidate = true; break; }
    }
    if (!candidate && basename_is_rom_artifact(base)) candidate = true;
    if (!candidate && name_has_rom_keyword(base)) candidate = true;
    if (!candidate && path_may_be_config_path(local)) candidate = true;
    if (!candidate && (strcmp(base, ".") == 0 || strcmp(base, "..") == 0)) candidate = true;
    if (!candidate) return false;

    char cwd[512];
    if (!read_cwd_path(cwd, sizeof(cwd))) return false;
    char full_path[1024];
    int n = snprintf(full_path, sizeof(full_path), "%s/%s", cwd, local);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(full_path)) return false;
    return is_rom_path(full_path);
}

bool custom_rom_hide_should_block_at(int dirfd, const char* path) {
    if (!path || reinterpret_cast<uintptr_t>(path) < 0x1000000) return false;
    if (!is_app_process()) return false;

    int saved_errno = errno;
    bool result = false;

    char local[512];
    if (safe_copy_string(path, local, sizeof(local)) < 0) {
        errno = saved_errno;
        return false;
    }

    if (proc_fd_alias_is_hidden(local)) {
        result = true;
    } else if (local[0] == '/') {
        result = is_rom_path(local);
    } else {
        size_t plen = strlen(local);
        bool candidate = plen > 0 && local[plen - 1] == '/';
        if (!candidate) {
            const char* base = path_basename(local);
            for (const char* const* dn = kBlockedDirnames; *dn; ++dn) {
                if (strcmp(base, *dn) == 0) { candidate = true; break; }
            }
            if (!candidate && basename_is_rom_artifact(base)) candidate = true;
            if (!candidate && name_has_rom_keyword(base)) candidate = true;
            if (!candidate && path_may_be_config_path(local)) candidate = true;
            if (!candidate && (strcmp(base, ".") == 0 || strcmp(base, "..") == 0)) candidate = true;
        }
        if (candidate) {
            char dir_path[512];
            bool have_dir = dirfd == AT_FDCWD
                    ? read_cwd_path(dir_path, sizeof(dir_path))
                    : resolve_fd_path(dirfd, dir_path, sizeof(dir_path));
            if (have_dir) {
                char full_path[1024];
                int n = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, local);
                if (n > 0 && static_cast<size_t>(n) < sizeof(full_path)) {
                    result = proc_fd_alias_is_hidden(full_path) || is_rom_path(full_path);
                }
            }
        }
    }

    errno = saved_errno;
    return result;
}

bool custom_rom_hide_is_symlink(const char* path) {
    int saved_errno = errno;
    struct stat sb;
    bool result = raw_fstatat(AT_FDCWD, path, &sb, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(sb.st_mode);
    errno = saved_errno;
    return result;
}

bool custom_rom_hide_is_empty_path(const char* path) {
    if (!path) return true;
    char local[2];
    return safe_copy_string(path, local, sizeof(local)) == 0;
}

bool custom_rom_hide_should_filter_dirent(int dirfd, const char* name) {
    if (!name || reinterpret_cast<uintptr_t>(name) < 0x1000000) return false;
    if (!is_app_process()) return false;

    if (name[0] == '.' && (name[1] == '\0'
            || (name[1] == '.' && name[2] == '\0'))) {
        return false;
    }

    bool maybe = false;
    for (const char* const* dn = kBlockedDirnames; *dn; ++dn) {
        if (strcmp(name, *dn) == 0) { maybe = true; break; }
    }
    if (!maybe && basename_is_rom_artifact(name)) maybe = true;
    if (!maybe && name_has_rom_keyword(name)) maybe = true;
    if (!maybe) return false;

    int saved_errno = errno;
    bool result = false;

    char dir_path[384];
    if (resolve_fd_path(dirfd, dir_path, sizeof(dir_path))) {
        char full_path[640];
        int n = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, name);
        if (n > 0 && static_cast<size_t>(n) < sizeof(full_path)) {
            // Overlays are hidden from listings only: apps open their own RROs by path.
            result = is_rom_path(full_path) || is_rom_overlay(full_path) ||
                     (dir_is_config(dir_path) && name_has_rom_keyword(name));
        }
    }

    errno = saved_errno;
    return result;
}

// Descriptor links expose the resolved proc path, not the alias used to open it.
static const char* canonicalize_proc_path(const char* path, char* resolved, size_t size) {
    if (strncmp(path, "/proc/", 6) != 0) return path;

    int saved_errno = errno;
    int fd = raw_openat(path, O_PATH | O_CLOEXEC);
    if (fd >= 0) {
        if (resolve_fd_path(fd, resolved, size)) path = resolved;
        raw_close(fd);
    }
    errno = saved_errno;
    return path;
}

static int create_encoded_memfd(const char* path) {
    char resolved_path[512];
    path = canonicalize_proc_path(path, resolved_path, sizeof(resolved_path));

    char memfd_name[250];
    int n = snprintf(memfd_name, sizeof(memfd_name), HIDE_MEMFD_NAME_PREFIX "%s", path);
    if (n < 0 || static_cast<size_t>(n) >= sizeof(memfd_name)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = raw_memfd_create(memfd_name, 0);
    if (fd >= 0) {
        pthread_once(&g_fd_meta_atfork_once, register_fd_meta_atfork);
        int saved_errno = errno;
        FdMeta meta = {};
        meta.sb_ok = raw_fstatat(AT_FDCWD, path, &meta.sb, 0) == 0;
        // Older kernels can reject the newest mask bits; STATX_ALL is the compatibility floor.
        meta.sx_ok = raw_statx(AT_FDCWD, path, 0, kStatxCaptureMask, &meta.sx) == 0;
        if (!meta.sx_ok && errno == EINVAL) {
            meta.sx_ok = raw_statx(AT_FDCWD, path, 0, STATX_ALL, &meta.sx) == 0;
        }
        if (meta.sb_ok || meta.sx_ok) store_fd_meta(fd, &meta);
        errno = saved_errno;
        register_fd(fd);
    }
    return fd;
}

static bool decode_encoded_memfd_link(const char* link, char* out, size_t out_size) {
    if (!link || !out || out_size == 0) return false;
    if (strncmp(link, HIDE_MEMFD_LINK_PREFIX, HIDE_MEMFD_LINK_PREFIX_LEN) != 0) return false;

    const char* real_path = link + HIDE_MEMFD_LINK_PREFIX_LEN;
    size_t real_len = strlen(real_path);
    const char* deleted_suffix = strstr(real_path, " (deleted)");
    if (deleted_suffix) real_len = static_cast<size_t>(deleted_suffix - real_path);
    if (real_len == 0 || real_len >= out_size) return false;

    memcpy(out, real_path, real_len);
    out[real_len] = '\0';
    return true;
}

static bool resolve_encoded_memfd_path(int fd, char* out, size_t out_size) {
    if (!is_tracked_fd(fd)) return false;

    char fd_path[512];
    if (!resolve_fd_path(fd, fd_path, sizeof(fd_path))) return false;
    bool decoded = decode_encoded_memfd_link(fd_path, out, out_size);
    if (!decoded) custom_rom_hide_unregister_fd(fd);
    return decoded;
}

static bool is_tracked_proc_fd_link(const char* path) {
    if (!path) return false;
    const char* number = nullptr;
    if (strncmp(path, "/proc/self/fd/", 14) == 0) number = path + 14;
    else if (strncmp(path, "/proc/thread-self/fd/", 21) == 0) number = path + 21;
    else if (strncmp(path, "/proc/", 6) == 0) {
        const char* p = path + 6;
        char* next = nullptr;
        long pid = strtol(p, &next, 10);
        if (p == next || pid != getpid() || strncmp(next, "/fd/", 4) != 0) return false;
        number = next + 4;
    }
    if (!number || *number < '0' || *number > '9') return false;
    char* end = nullptr;
    long fd = strtol(number, &end, 10);
    return end && *end == '\0' && fd >= 0 && fd < HIDE_TRACKED_FD_LIMIT &&
           is_tracked_fd(static_cast<int>(fd));
}

ssize_t custom_rom_hide_readlinkat_post(int dirfd, const char* path, char* buf,
                                        size_t size, ssize_t ret) {
    if (ret <= 0 || !buf || !is_app_process()) return ret;
    int saved_errno = errno;
    bool has_prefix = ret >= static_cast<ssize_t>(HIDE_MEMFD_LINK_PREFIX_LEN) &&
                      memcmp(buf, HIDE_MEMFD_LINK_PREFIX, HIDE_MEMFD_LINK_PREFIX_LEN) == 0;
    if (!has_prefix && !is_tracked_proc_fd_link(path)) {
        errno = saved_errno;
        return ret;
    }

    char link[512];
    ssize_t n = syscall(__NR_readlinkat, dirfd, path, link, sizeof(link) - 1);
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(link) - 1) {
        errno = saved_errno;
        return ret;
    }
    link[n] = '\0';
    char real_path[512];
    if (!decode_encoded_memfd_link(link, real_path, sizeof(real_path))) {
        errno = saved_errno;
        return ret;
    }
    size_t path_len = strlen(real_path);
    size_t to_copy = path_len < size ? path_len : size;
    memcpy(buf, real_path, to_copy);
    errno = saved_errno;
    return static_cast<ssize_t>(to_copy);
}

enum ProcFilterType {
    PROC_FILTER_NONE, PROC_FILTER_MAPS, PROC_FILTER_SMAPS, PROC_FILTER_MOUNTS,
    PROC_FILTER_MOUNTINFO, PROC_FILTER_FILESYSTEMS, PROC_FILTER_CMDLINE,
};

static ProcFilterType get_proc_filter_type(const char* path) {
    if (!path || reinterpret_cast<uintptr_t>(path) < 0x1000000) return PROC_FILTER_NONE;
    if (strcmp(path, "/proc/cmdline") == 0) return PROC_FILTER_CMDLINE;
    if (strcmp(path, "/proc/filesystems") == 0) return PROC_FILTER_FILESYSTEMS;
    if (strncmp(path, "/proc/", 6) != 0) return PROC_FILTER_NONE;

    const char* leaf = nullptr;
    if (strncmp(path, "/proc/self/", 11) == 0) leaf = path + 11;
    else if (strncmp(path, "/proc/thread-self/", 18) == 0) leaf = path + 18;
    else {
        const char* p = path + 6;
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '/' && *(p + 1) != '\0') leaf = p + 1;
        else leaf = path + 6;
    }

    if (!leaf) return PROC_FILTER_NONE;

    const char* leaf_base = strrchr(leaf, '/');
    leaf_base = leaf_base ? leaf_base + 1 : leaf;

    if (strcmp(leaf_base, "maps") == 0) return PROC_FILTER_MAPS;
    if (strcmp(leaf_base, "smaps") == 0) return PROC_FILTER_SMAPS;
    if (strcmp(leaf_base, "mounts") == 0) return PROC_FILTER_MOUNTS;
    if (strcmp(leaf_base, "mountinfo") == 0) return PROC_FILTER_MOUNTINFO;

    return PROC_FILTER_NONE;
}

static bool line_has_blocked_segment(const char* line) {
    const char* path = strchr(line, '/');
    if (!path) return false;

    if (is_rom_framework_artifact(path)) return true;
    if (is_rom_overlay(path)) return true;

    for (const PrefixEntry* kw = kProcFilterKeywords; kw->str; ++kw) {
        const char* p = path;
        while ((p = strstr(p, kw->str)) != nullptr) {
            char before = (p == line) ? '/' : p[-1];
            char after = p[kw->len];
            bool lb = before == '/' || before == ' ' || before == '\0';
            bool rb = after == '/' || after == ' ' || after == '.' || after == '\0' || after == '\n';
            if (lb && rb) return true;
            p += kw->len;
        }
    }
    return false;
}

static bool line_contains_any(const char* line, const char* const* keywords) {
    for (const char* const* kw = keywords; *kw; ++kw) {
        if (strstr(line, *kw) != nullptr) return true;
    }
    return false;
}

static bool should_filter_line(ProcFilterType type, const char* line) {
    switch (type) {
        case PROC_FILTER_MAPS: return line_has_blocked_segment(line);
        case PROC_FILTER_MOUNTS:
        case PROC_FILTER_MOUNTINFO: return line_contains_any(line, kMountFilterKeywords);
        case PROC_FILTER_FILESYSTEMS: return strstr(line, "overlay") != nullptr;
        default: return false;
    }
}

static char* read_file_raw(const char* path, size_t* out_size) {
    int fd = raw_openat(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return nullptr;

    constexpr size_t kMaxFileBytes = 64 * 1024 * 1024;
    size_t capacity = 16384;
    size_t size = 0;
    char* buf = static_cast<char*>(malloc(capacity));
    if (!buf) { raw_close(fd); return nullptr; }

    while (true) {
        if (size == capacity - 1) {
            if (capacity >= kMaxFileBytes + 1) {
                errno = EFBIG;
                break;
            }
            size_t grown = capacity * 2;
            if (grown > kMaxFileBytes + 1) grown = kMaxFileBytes + 1;
            char* next = static_cast<char*>(realloc(buf, grown));
            if (!next) break;
            buf = next;
            capacity = grown;
        }
        ssize_t n = raw_read(fd, buf + size, capacity - size - 1);
        if (n > 0) { size += static_cast<size_t>(n); continue; }
        if (n == 0) {
            buf[size] = '\0';
            raw_close(fd);
            *out_size = size;
            return buf;
        }
        if (errno == EINTR) continue;
        break;
    }
    int saved_errno = errno;
    free(buf);
    raw_close(fd);
    errno = saved_errno;
    return nullptr;
}

typedef bool (*LinePredicate)(const char* line, void* ctx);
typedef bool (*LineWriter)(int mem_fd, char* line, size_t line_len, void* ctx);

static bool raw_write_all(int fd, const void* buffer, size_t size) {
    const char* data = static_cast<const char*>(buffer);
    while (size != 0) {
        ssize_t n = raw_write(fd, data, size);
        if (n > 0) {
            size -= static_cast<size_t>(n);
            data += n;
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n == 0) errno = EIO;
        return false;
    }
    return true;
}

static bool write_line_raw(int fd, char* line, size_t len, void*) {
    return raw_write_all(fd, line, len);
}

static int filter_file_with(const char* path, LinePredicate drop, LineWriter writer, void* ctx) {
    size_t file_size = 0;
    char* content = read_file_raw(path, &file_size);
    if (!content) return -1;

    int mem_fd = create_encoded_memfd(path);
    if (mem_fd < 0) {
        free(content);
        return -1;
    }

    bool ok = true;
    char* pos = content;
    char* end = content + file_size;
    while (pos < end) {
        char* eol = static_cast<char*>(memchr(pos, '\n', end - pos));
        size_t line_len = eol ? static_cast<size_t>(eol - pos + 1)
                              : static_cast<size_t>(end - pos);
        char saved = pos[line_len];
        pos[line_len] = '\0';
        if ((!drop || !drop(pos, ctx)) &&
            !(writer ? writer : write_line_raw)(mem_fd, pos, line_len, ctx)) {
            ok = false;
        }
        pos[line_len] = saved;
        if (!ok) break;
        pos += line_len;
    }

    free(content);
    if (ok && raw_lseek(mem_fd, 0, SEEK_SET) >= 0) return mem_fd;
    int saved_errno = errno;
    custom_rom_hide_unregister_fd(mem_fd);
    raw_close(mem_fd);
    errno = saved_errno;
    return -1;
}

static void replace_all_cmdline(char* content, size_t len, const char* needle, size_t needle_len,
                                const char* replacement, size_t replacement_len) {
    if (needle_len == 0 || needle_len != replacement_len) return;

    char* end = content + strnlen(content, len);
    for (char* p = content; p < end;) {
        char* hit = strstr(p, needle);
        if (!hit || hit >= end) break;
        memcpy(hit, replacement, needle_len);
        p = hit + needle_len;
    }
}

#define REPLACE_CMDLINE_LITERAL(content, len, needle, replacement) \
    do { \
        static_assert(sizeof(needle) == sizeof(replacement), \
                      "cmdline replacement must preserve byte length"); \
        replace_all_cmdline(content, len, needle, sizeof(needle) - 1, replacement, \
                            sizeof(replacement) - 1); \
    } while (false)

static bool filter_cmdline(int mem_fd, char* content, size_t len) {
    REPLACE_CMDLINE_LITERAL(content, len, "androidboot.verifiedbootstate=orange", "androidboot.verifiedbootstate=green ");
    REPLACE_CMDLINE_LITERAL(content, len, "androidboot.verifiedbootstate=yellow", "androidboot.verifiedbootstate=green ");
    REPLACE_CMDLINE_LITERAL(content, len, "androidboot.flash.locked=0", "androidboot.flash.locked=1");
    REPLACE_CMDLINE_LITERAL(content, len, "androidboot.vbmeta.device_state=unlocked", "androidboot.vbmeta.device_state=locked  ");
    return raw_write_all(mem_fd, content, strnlen(content, len));
}

struct BuildPropLine {
    const char* start;
    const char* key;
    size_t key_len;
    const char* eq;
    const char* value;
    size_t value_len;
    bool has_cr;
    bool has_nl;
    bool valid;
};

static BuildPropLine parse_build_prop_line(const char* line) {
    BuildPropLine p = {};
    if (!line) return p;

    p.start = line;
    while (*line == ' ' || *line == '\t') ++line;
    if (*line == '\0' || *line == '\n' || *line == '\r' || *line == '#') return p;

    const char* eq = line;
    while (*eq && *eq != '=' && *eq != '\n' && *eq != '\r') ++eq;
    if (*eq != '=') return p;

    p.key = line;
    p.eq = eq;
    p.key_len = static_cast<size_t>(eq - line);
    while (p.key_len > 0 &&
           (line[p.key_len - 1] == ' ' || line[p.key_len - 1] == '\t')) {
        --p.key_len;
    }
    if (p.key_len == 0) return p;

    const char* value = eq + 1;
    const char* end = value;
    while (*end && *end != '\n' && *end != '\r') ++end;
    p.value = value;
    p.value_len = static_cast<size_t>(end - value);
    p.has_cr = (*end == '\r');
    p.has_nl = (*end == '\n') || (p.has_cr && end[1] == '\n');
    p.valid = true;
    return p;
}

static bool copy_build_prop_key(const BuildPropLine& p, char* key, size_t key_size) {
    if (!p.valid || !key || p.key_len >= key_size) return false;
    memcpy(key, p.key, p.key_len);
    key[p.key_len] = '\0';
    return true;
}

static bool is_rom_identity_prop_name(const char* key) {
    static const char kEvolution[] = "ro.evolution.";
    static const char kLineage[] = "ro.lineage.";
    static const char kCm[] = "ro.cm.";
    static const char kModversion[] = "ro.modversion";
    return strncmp(key, kEvolution, sizeof(kEvolution) - 1) == 0 ||
           strncmp(key, kLineage, sizeof(kLineage) - 1) == 0 ||
           strncmp(key, kCm, sizeof(kCm) - 1) == 0 ||
           strcmp(key, kModversion) == 0;
}

static bool value_has_rom_keyword(const BuildPropLine& p) {
    if (!p.valid || p.value_len == 0) return false;
    for (const PrefixEntry* kw = kProcFilterKeywords; kw->str; ++kw) {
        if (kw->len <= p.value_len) {
            for (size_t i = 0; i + kw->len <= p.value_len; ++i) {
                if (memcmp(p.value + i, kw->str, kw->len) == 0) return true;
            }
        }
    }
    return false;
}

// DroidGuard reads build.prop directly as well as through the property service.
// Drop hidden/ROM-specific keys, and let the writer below substitute every key
// that has a PIF or fixed override, so the file agrees with the property API.
static bool drop_build_prop_line(const char* line, void*) {
    BuildPropLine p = parse_build_prop_line(line);
    if (!p.valid) return false;

    char key[128];
    if (!copy_build_prop_key(p, key, sizeof(key))) return false;

    if (custom_rom_hide_should_hide_prop(key)) return true;

    char override_buffer[PROP_VALUE_MAX];
    if (custom_rom_hide_get_prop_override(key, override_buffer)) return false;

    if (is_rom_identity_prop_name(key)) return true;
    return value_has_rom_keyword(p);
}

static bool write_build_prop_override(int mem_fd, char* line, size_t line_len, void*) {
    BuildPropLine p = parse_build_prop_line(line);
    char key[128];
    if (!p.valid || !copy_build_prop_key(p, key, sizeof(key))) {
        return raw_write_all(mem_fd, line, line_len);
    }

    char override_buffer[PROP_VALUE_MAX];
    const char* override_value = custom_rom_hide_get_prop_override(key, override_buffer);
    if (!override_value) return raw_write_all(mem_fd, line, line_len);

    if (!raw_write_all(mem_fd, p.start, static_cast<size_t>(p.eq - p.start + 1)) ||
        !raw_write_all(mem_fd, override_value, strlen(override_value))) {
        return false;
    }
    if (p.has_cr && !raw_write_all(mem_fd, "\r", 1)) return false;
    if (p.has_nl && !raw_write_all(mem_fd, "\n", 1)) return false;
    return true;
}

static const char* const kBuildPropPaths[] = {
    "/system/build.prop",
    "/vendor/build.prop",
    "/product/build.prop",
    "/system_ext/build.prop",
    "/odm/build.prop",
    "/system/etc/prop.default",
    "/vendor/default.prop",
    "/system_root/build.prop",
    "/root/build.prop",
    "/system/system/build.prop",
    nullptr
};

static bool is_build_prop_path(const char* path) {
    if (!path) return false;
    for (const char* const* p = kBuildPropPaths; *p; ++p) {
        if (strcmp(path, *p) == 0) return true;
    }
    const char* base = path_basename(path);
    return strcmp(base, "build.prop") == 0 ||
           strcmp(base, "prop.default") == 0 ||
           strcmp(base, "default.prop") == 0;
}

static bool path_may_be_build_prop(const char* path) {
    if (!path) return false;
    const char* base = path_basename(path);
    return strcmp(base, "build.prop") == 0 ||
           strcmp(base, "prop.default") == 0 ||
           strcmp(base, "default.prop") == 0;
}

static bool resolve_proc_path_via_open(const char* path, char* out, size_t out_size) {
    int saved_errno = errno;
    int fd = raw_openat(path, O_PATH | O_CLOEXEC);
    if (fd < 0) {
        errno = saved_errno;
        return false;
    }

    bool resolved = resolve_fd_path(fd, out, out_size);
    raw_close(fd);
    errno = saved_errno;
    return resolved;
}

static bool resolve_proc_fd_path(const char* path, char* out, size_t out_size) {
    static const char kSelf[] = "/proc/self/fd/";
    static const char kThread[] = "/proc/thread-self/fd/";
    static const char kDev[] = "/dev/fd/";

    const char* p = nullptr;
    if (strncmp(path, kSelf, sizeof(kSelf) - 1) == 0) {
        p = path + sizeof(kSelf) - 1;
    } else if (strncmp(path, kThread, sizeof(kThread) - 1) == 0) {
        p = path + sizeof(kThread) - 1;
    } else if (strncmp(path, kDev, sizeof(kDev) - 1) == 0) {
        p = path + sizeof(kDev) - 1;
    }
    if (!p) {
        if (strncmp(path, "/proc/", 6) != 0) return false;
        if (strstr(path, "/root") == nullptr && strstr(path, "/cwd") == nullptr &&
            strstr(path, "/fd/") == nullptr) {
            return false;
        }
        return resolve_proc_path_via_open(path, out, out_size);
    }
    if (*p == '\0') return false;

    int fd = 0;
    for (; *p >= '0' && *p <= '9'; ++p) {
        if (fd > 1000000) return false;
        fd = fd * 10 + (*p - '0');
    }
    if (*p != '\0') {
        return strstr(path, "/fd/") != nullptr &&
               resolve_proc_path_via_open(path, out, out_size);
    }
    return resolve_fd_path(fd, out, out_size);
}

bool custom_rom_hide_resolve_proc_fd_path(const char* path, char* out, size_t out_size) {
    if (!path) return false;
    return resolve_proc_fd_path(path, out, out_size);
}

int custom_rom_hide_filter_build_prop(int dirfd, const char* path) {
    if (!path || reinterpret_cast<uintptr_t>(path) < 0x1000000) return -1;

    char resolved[512];
    if (resolve_proc_fd_path(path, resolved, sizeof(resolved))) {
        if (!is_build_prop_path(resolved)) return -1;
    } else {
        if (!path_may_be_build_prop(path)) return -1;
        if (!resolve_path_at(dirfd, path, resolved, sizeof(resolved))) return -1;
        if (!is_build_prop_path(resolved)) return -1;
    }
    if (!is_app_process() || !is_droidguard_process()) return -1;

    int saved_errno = errno;
    int mem_fd = filter_file_with(resolved, drop_build_prop_line, write_build_prop_override, nullptr);
    errno = saved_errno;
    return mem_fd;
}

struct MountDm { const char* mnt; const char* dev; };
static const MountDm kMountDm[] = {
    { " /system ",     "/dev/block/dm-0" },
    { " /vendor ",     "/dev/block/dm-1" },
    { " /product ",    "/dev/block/dm-2" },
    { " /system_ext ", "/dev/block/dm-3" },
    { " /odm ",        "/dev/block/dm-4" },
    { nullptr,         nullptr },
};

static bool write_spoofed_mount_line(int mem_fd, char* line, size_t line_len, void*) {
    char* rw_delim = strstr(line, ",rw,");
    if (rw_delim) { rw_delim[1] = 'r'; rw_delim[2] = 'o'; }
    rw_delim = strstr(line, " rw,");
    if (rw_delim) { rw_delim[1] = 'r'; rw_delim[2] = 'o'; }
    rw_delim = strstr(line, ",rw ");
    if (rw_delim) { rw_delim[1] = 'r'; rw_delim[2] = 'o'; }

    if (!strstr(line, "/dev/block/loop")) {
        const char* replacement = nullptr;
        for (const MountDm* m = kMountDm; m->mnt; ++m) {
            if (strstr(line, m->mnt)) { replacement = m->dev; break; }
        }
        if (!replacement &&
            (strstr(line, " / / ") || strstr(line, " / ext4") ||
             strstr(line, " / erofs") || strstr(line, " / f2fs")))
            replacement = "/dev/block/dm-0";

        if (replacement) {
            char* dev_start = strstr(line, "/dev/block/");
            if (!dev_start) dev_start = strstr(line, "/dev/root");

            if (dev_start) {
                char* dev_end = strchr(dev_start, ' ');
                if (!dev_end) dev_end = dev_start + strlen(dev_start);
                return raw_write_all(mem_fd, line, dev_start - line) &&
                       raw_write_all(mem_fd, replacement, strlen(replacement)) &&
                       raw_write_all(mem_fd, dev_end, line_len - (dev_end - line));
            }
        }
    }
    return raw_write_all(mem_fd, line, line_len);
}

static bool drop_proc_line(const char* line, void* ctx) {
    return should_filter_line(*static_cast<ProcFilterType*>(ctx), line);
}

static bool is_smaps_header(const char* line) {
    if (line[0] == '\0') return false;
    return (line[0] >= '0' && line[0] <= '9') || (line[0] >= 'a' && line[0] <= 'f');
}

struct SmapsFilterCtx {
    bool dropping;
};

static bool drop_smaps_line(const char* line, void* raw_ctx) {
    SmapsFilterCtx* ctx = static_cast<SmapsFilterCtx*>(raw_ctx);
    if (is_smaps_header(line)) {
        ctx->dropping = line_has_blocked_segment(line);
        return ctx->dropping;
    }
    return ctx->dropping;
}

int custom_rom_hide_filter_proc(const char* path) {
    if (!is_app_process()) return -1;
    if (!path || reinterpret_cast<uintptr_t>(path) < 0x1000000) return -1;

    int saved_errno = errno;
    ProcFilterType type = get_proc_filter_type(path);
    if (type == PROC_FILTER_NONE) { errno = saved_errno; return -1; }

    if (type == PROC_FILTER_SMAPS) {
        SmapsFilterCtx ctx = {};
        int mem_fd = filter_file_with(path, drop_smaps_line, write_line_raw, &ctx);
        errno = saved_errno;
        return mem_fd;
    }

    if (type != PROC_FILTER_CMDLINE) {
        LineWriter writer = (type == PROC_FILTER_MOUNTS || type == PROC_FILTER_MOUNTINFO)
                ? write_spoofed_mount_line : write_line_raw;
        int mem_fd = filter_file_with(path, drop_proc_line, writer, &type);
        errno = saved_errno;
        return mem_fd;
    }

    size_t file_size = 0;
    char* content = read_file_raw(path, &file_size);
    if (!content) { errno = saved_errno; return -1; }

    int mem_fd = create_encoded_memfd(path);
    if (mem_fd < 0) { free(content); errno = saved_errno; return -1; }

    bool ok = filter_cmdline(mem_fd, content, file_size);
    free(content);
    if (!ok || raw_lseek(mem_fd, 0, SEEK_SET) < 0) {
        custom_rom_hide_unregister_fd(mem_fd);
        raw_close(mem_fd);
        errno = saved_errno;
        return -1;
    }
    errno = saved_errno;
    return mem_fd;
}

static bool is_selinux_policy_path(const char* path) {
    static const PrefixEntry kSelinuxDirs[] = {
        PE("/system/etc/selinux"), PE("/system_ext/etc/selinux"),
        PE("/product/etc/selinux"), PE("/vendor/etc/selinux"),
        PE("/odm/etc/selinux"), {nullptr, 0}
    };
    bool in_system_policy_dir = false;
    for (const PrefixEntry* entry = kSelinuxDirs; entry->str; ++entry) {
        if (strncmp(path, entry->str, entry->len) == 0 && path[entry->len] == '/') {
            in_system_policy_dir = true;
            break;
        }
    }
    if (!in_system_policy_dir) return false;
    const char* base = path_basename(path);
    return strstr(base, "_contexts") != nullptr ||
           strstr(base, "sepolicy.cil") != nullptr;
}

static bool line_has_rom_keyword(const char* line) {
    for (const PrefixEntry* kw = kProcFilterKeywords; kw->str; ++kw) {
        if (strstr(line, kw->str) != nullptr) return true;
    }
    return false;
}

static bool drop_sepolicy_line(const char* line, void*) {
    return line_has_rom_keyword(line);
}

int custom_rom_hide_filter_sepolicy(const char* path) {
    if (!path) return -1;
    if (!is_app_process()) return -1;
    if (!path || reinterpret_cast<uintptr_t>(path) < 0x1000000) return -1;

    int saved_errno = errno;
    if (!is_selinux_policy_path(path)) { errno = saved_errno; return -1; }

    int mem_fd = filter_file_with(path, drop_sepolicy_line, write_line_raw, nullptr);
    errno = saved_errno;
    return mem_fd;
}

#ifndef CUSTOM_ROM_HIDE_FILTER_VINTF
#define CUSTOM_ROM_HIDE_FILTER_VINTF 1
#endif

#if CUSTOM_ROM_HIDE_FILTER_VINTF
static const char* const kVintfFilterPaths[] = {
    "/system/etc/vintf/compatibility_matrix.xml", "/system/etc/vintf/compatibility_matrix.device.xml",
    "/vendor/etc/vintf/compatibility_matrix.xml", "/vendor/etc/vintf/compatibility_matrix.device.xml",
    "/product/etc/vintf/compatibility_matrix.xml", "/product/etc/vintf/compatibility_matrix.device.xml",
    "/system_ext/etc/vintf/compatibility_matrix.xml", "/system_ext/etc/vintf/compatibility_matrix.device.xml",
    "/odm/etc/vintf/compatibility_matrix.xml", "/odm/etc/vintf/compatibility_matrix.device.xml",
    "/system/etc/vintf/manifest.xml", "/vendor/etc/vintf/manifest.xml", "/product/etc/vintf/manifest.xml",
    "/system_ext/etc/vintf/manifest.xml", "/odm/etc/vintf/manifest.xml", nullptr
};

static const char* const kVintfFilterKeywords[] = {
    "lineage", "Lineage", "evolution", "Evolution", nullptr
};
#endif

int custom_rom_hide_filter_vintf(const char* path) {
#if !CUSTOM_ROM_HIDE_FILTER_VINTF
    (void) path;
    return -1;
#else
    if (!is_app_process()) return -1;
    if (!path || reinterpret_cast<uintptr_t>(path) < 0x1000000) return -1;

    int saved_errno = errno;
    bool match = false;
    for (const char* const* p = kVintfFilterPaths; *p; ++p) {
        if (strcmp(path, *p) == 0) { match = true; break; }
    }
    if (!match) { errno = saved_errno; return -1; }

    struct VintfCtx {
        int skip_depth;
    } ctx = {};
    int mem_fd = filter_file_with(path, [](const char* line, void* raw_ctx) {
        VintfCtx* ctx = static_cast<VintfCtx*>(raw_ctx);
        bool keyword_hit = line_contains_any(line, kVintfFilterKeywords);
        bool opens_block = strstr(line, "<hal") != nullptr || strstr(line, "<interface") != nullptr;
        bool closes_block = strstr(line, "</hal>") != nullptr || strstr(line, "</interface>") != nullptr;

        if (ctx->skip_depth > 0) {
            if (opens_block) ctx->skip_depth++;
            if (closes_block) ctx->skip_depth--;
            return true;
        }
        if (keyword_hit) {
            if (opens_block && !closes_block) ctx->skip_depth = 1;
            return true;
        }
        return false;
    }, write_line_raw, &ctx);
    if (mem_fd >= 0 && ctx.skip_depth != 0) {
        custom_rom_hide_unregister_fd(mem_fd);
        raw_close(mem_fd);
        errno = saved_errno;
        return -1;
    }
    errno = saved_errno;
    return mem_fd;
#endif
}

static const char* const kSpoofedEmptyProps[] = {
    "ro.evolution.version", "ro.evolution.build.version", "ro.evolution.display.version",
    "ro.lineage.version", "ro.lineage.build.version", "ro.cm.build.version",
    "ro.modversion", "init.svc_debug_pid.adb_root",
    "init.svc.adb_root", "service.adb.root", nullptr
};

// DroidGuard also enumerates the property area, so an empty value is not enough:
// remove the key itself from find/foreach in that process. Normal apps keep seeing
// these props; direct value reads still honor an exact configured PIF override.
static const char* const kDroidGuardHiddenProps[] = {
    "ro.evolution.device", "ro.lineage.device", "ro.cm.device", nullptr
};

static bool is_hidden_droidguard_prop(const char* name) {
    for (const char* const* p = kDroidGuardHiddenProps; *p; ++p) {
        if (strcmp(name, *p) == 0) return is_droidguard_process();
    }
    return false;
}

struct PropOverride { const char* name; const char* value; };
static const PropOverride kSpoofedValueProps[] = {
    {"ro.debuggable", "0"},
    {"ro.build.type", "user"},
    {"ro.build.tags", "release-keys"},
    {"ro.system.build.type", "user"},
    {"ro.system.build.tags", "release-keys"},
    {"ro.vendor.build.type", "user"},
    {"ro.vendor.build.tags", "release-keys"},
    {"ro.secure", "1"},
    {"ro.adb.secure", "1"},
    // Boot state as stock reports it on a locked device, matching the cmdline
    // rewrite in filter_cmdline(). App processes only (see is_app_process()), so
    // system_server's OemLock/PersistentDataBlock checks still see the real state.
    {"ro.boot.verifiedbootstate", "green"},
    {"vendor.boot.verifiedbootstate", "green"},
    {"ro.boot.vbmeta.device_state", "locked"},
    {"vendor.boot.vbmeta.device_state", "locked"},
    {"ro.boot.flash.locked", "1"},
    {"ro.boot.veritymode", "enforcing"},
    {"ro.secureboot.lockstate", "locked"},
    {nullptr, nullptr}
};

// Read-only keys that mirror whatever AxSpoofManager staged into the matching
// persist.sys.pif.* prop after a fingerprint refresh. Unlike kSpoofedValueProps
// these have no fixed value — read at call time, only applied when the staging
// prop is actually set (empty = no PIF config loaded yet, so don't blank out the
// real device identity), and only served to the DroidGuard process.
struct DynamicPropOverride { const char* name; const char* staging_name; };
static const DynamicPropOverride kDynamicProductProps[] = {
    {"ro.product.manufacturer",        "persist.sys.pif.product.manufacturer"},
    {"ro.product.brand",               "persist.sys.pif.product.brand"},
    {"ro.product.model",               "persist.sys.pif.product.model"},
    {"ro.product.device",              "persist.sys.pif.product.device"},
    {"ro.product.name",                "persist.sys.pif.product.name"},
    {"ro.product.system.manufacturer", "persist.sys.pif.product.manufacturer"},
    {"ro.product.system.brand",        "persist.sys.pif.product.brand"},
    {"ro.product.system.model",        "persist.sys.pif.product.model"},
    {"ro.product.vendor.manufacturer", "persist.sys.pif.product.manufacturer"},
    {"ro.product.vendor.brand",        "persist.sys.pif.product.brand"},
    {"ro.product.vendor.model",        "persist.sys.pif.product.model"},
    {"ro.build.product",               "persist.sys.pif.product.device"},
    {"ro.build.display.id",             "persist.sys.pif.build.id"},
    {"ro.build.description",           "persist.sys.pif.build.description"},
    {"ro.build.flavor",                "persist.sys.pif.build.flavor"},
    {nullptr, nullptr}
};

// ro.product.<partition>.<field> for every partition (system, vendor, odm, product,
// system_ext, the *_dlkm ones, ...), served from the same staged product identity as the
// table above. A stock Pixel reports one identity on all of them, and the ROM's own device
// and name would otherwise show through on the partitions that table doesn't list.
static const char* find_product_partition_staging(const char* name) {
    static const char kPrefix[] = "ro.product.";
    if (strncmp(name, kPrefix, sizeof(kPrefix) - 1) != 0) return nullptr;
    const char* partition = name + sizeof(kPrefix) - 1;
    const char* dot = partition;
    while (*dot && *dot != '.') ++dot;
    if (dot == partition || *dot != '.') return nullptr;  // needs "<partition>.<field>"
    const char* field = dot + 1;
    for (const char* c = field; *c; ++c) {
        if (*c == '.') return nullptr;
    }
    if (strcmp(field, "manufacturer") == 0) return "persist.sys.pif.product.manufacturer";
    if (strcmp(field, "brand") == 0) return "persist.sys.pif.product.brand";
    if (strcmp(field, "model") == 0) return "persist.sys.pif.product.model";
    if (strcmp(field, "device") == 0) return "persist.sys.pif.product.device";
    if (strcmp(field, "name") == 0) return "persist.sys.pif.product.name";
    return nullptr;
}

// PIFork's leading-* wildcard properties: every read-only prop ending in the
// suffix is served the same staged value, so partitions the table above would
// have to list one by one (vendor_dlkm, odm, bootimage, ...) are covered as
// well. Only "ro." keys match. That also keeps the persist.sys.pif.* staging
// props themselves out of the match, which end in these suffixes too and
// would send the staging read back through this lookup.
struct DynamicSuffixOverride { const char* suffix; size_t suffix_len; const char* staging_name; };
#define DYNAMIC_SUFFIX(suffix, staging) { suffix, sizeof(suffix) - 1, staging }
static const DynamicSuffixOverride kDynamicSuffixProps[] = {
    DYNAMIC_SUFFIX(".build.id",        "persist.sys.pif.build.id"),
    DYNAMIC_SUFFIX(".build.display.id", "persist.sys.pif.build.id"),
    DYNAMIC_SUFFIX(".build.description", "persist.sys.pif.build.description"),
    DYNAMIC_SUFFIX(".build.flavor",    "persist.sys.pif.build.flavor"),
    DYNAMIC_SUFFIX(".build.product",   "persist.sys.pif.product.device"),
    DYNAMIC_SUFFIX(".security_patch",  "persist.sys.pif.security_patch"),
    DYNAMIC_SUFFIX("api_level",        "persist.sys.pif.api_level"),
    // ro.build.version.real_security_patch, which ".security_patch" does not reach.
    DYNAMIC_SUFFIX(".real_security_patch", "persist.sys.pif.security_patch"),
    // Build description/flavor/product/display and type/tags for the partitions
    // kSpoofedValueProps does not pin (odm, product, system_ext, bootimage, ...),
    // all taken from the same staged PIF identity as the fingerprint.
    DYNAMIC_SUFFIX(".build.type",      "persist.sys.pif.build.type"),
    DYNAMIC_SUFFIX(".build.tags",      "persist.sys.pif.build.tags"),
    {nullptr, 0, nullptr}
};

static bool has_prop_suffix(const char* name, const char* suffix) {
    size_t name_len = strlen(name);
    size_t suffix_len = strlen(suffix);
    return name_len > suffix_len && strcmp(name + name_len - suffix_len, suffix) == 0;
}

// Fixed values served to DroidGuard only, as PIFork's property hook does. adbd
// and USB state are read by init, system_server and Settings; none of them is
// DroidGuard, so they keep the real values. Applied on both the direct
// __system_property_get/__system_property_read paths and the property
// callback/serial path; the dynamic tables above stay callback-only.
//
// The ROM identity props are written by the build itself (soong's
// gen_build_prop.py) and would let a DroidGuard prop probe name the ROM.
// Device keys are served empty, build user/host are normalized, and every
// other process keeps the real values - including the ROM's own apps that
// match device on them (the PIF device matcher, the Updater and model page).
static const PropOverride kDroidGuardValueProps[] = {
    {"init.svc.adbd", "stopped"},
    {"sys.usb.state", "mtp"},
    {"ro.build.user", "android-build"},
    {"ro.build.host", "android-build"},
    {"ro.evolution.device", ""},
    {"ro.lineage.device", ""},
    {nullptr, nullptr}
};

// Shared by the direct read paths and the callback/serial path.
static const char* find_droidguard_value_override(const char* name) {
    for (const PropOverride* o = kDroidGuardValueProps; o->name; ++o) {
        if (strcmp(name, o->name) == 0) return o->value;
    }
    // Partition build.prop files carry the same build user/host as ro.build.
    // Keep those fields consistent without blanking hardware identity.
    if (strncmp(name, "ro.", 3) == 0 &&
        (has_prop_suffix(name, ".build.user") || has_prop_suffix(name, ".build.host"))) {
        return "android-build";
    }
    return nullptr;
}

static const DynamicSuffixOverride* find_dynamic_suffix_override(const char* name) {
    if (strncmp(name, "ro.", 3) != 0) return nullptr;
    size_t len = strlen(name);
    for (const DynamicSuffixOverride* o = kDynamicSuffixProps; o->suffix; ++o) {
        if (len > o->suffix_len && strcmp(name + len - o->suffix_len, o->suffix) == 0) return o;
    }
    return nullptr;
}

// The staging props only exist to feed the DroidGuard overrides above. Hide them
// from every other app process so a plain getprop can't reveal them; the override
// lookup itself runs inside DroidGuard and still reads them.
#define PIF_STAGING_PROP_PREFIX "persist.sys.pif."

static bool is_hidden_staging_prop(const char* name) {
    return strncmp(name, PIF_STAGING_PROP_PREFIX, sizeof(PIF_STAGING_PROP_PREFIX) - 1) == 0 &&
           !is_droidguard_process();
}

// Entries from the PIF config that the tables above don't cover: exact property names and
// leading-* suffix wildcards, like PIFork's jsonProps. AxSpoofManager stages them as
// persist.sys.pif.x.<i> = "name=value" ("*suffix=value" for a wildcard), sorted by key, with
// persist.sys.pif.x.count saying how many slots are live. Keep the names and the slot limit
// in sync with AxSpoofManager.
//
// Like PIFork an exact match beats every wildcard, and the first matching wildcard wins.
// A bare "*" is ignored, since it would match every property. Only called from the
// DroidGuard process, and never for the staging props themselves.
#define PIF_CUSTOM_COUNT_PROP "persist.sys.pif.x.count"
#define PIF_CUSTOM_SLOT_PREFIX "persist.sys.pif.x."
#define PIF_CUSTOM_SLOT_MAX 32

static const char* find_custom_prop_override(const char* name, char* buffer, bool wildcard) {
    if (strncmp(name, PIF_STAGING_PROP_PREFIX, sizeof(PIF_STAGING_PROP_PREFIX) - 1) == 0) {
        return nullptr;
    }
    // This code is also linked into the loader, so stick to plain string operations.
    char raw[PROP_VALUE_MAX];
    if (__system_property_get(PIF_CUSTOM_COUNT_PROP, raw) <= 0) return nullptr;
    int count = 0;
    for (const char* c = raw; *c >= '0' && *c <= '9' && count < 1000; ++c) {
        count = count * 10 + (*c - '0');
    }
    if (count > PIF_CUSTOM_SLOT_MAX) count = PIF_CUSTOM_SLOT_MAX;

    const size_t name_len = strlen(name);
    char slot[sizeof(PIF_CUSTOM_SLOT_PREFIX) + 3];
    memcpy(slot, PIF_CUSTOM_SLOT_PREFIX, sizeof(PIF_CUSTOM_SLOT_PREFIX) - 1);
    for (int i = 0; i < count; ++i) {
        char* p = slot + sizeof(PIF_CUSTOM_SLOT_PREFIX) - 1;
        if (i >= 10) *p++ = static_cast<char>('0' + i / 10);
        *p++ = static_cast<char>('0' + i % 10);
        *p = '\0';

        char entry[PROP_VALUE_MAX];
        if (__system_property_get(slot, entry) <= 0) continue;
        char* eq = entry;
        while (*eq && *eq != '=') ++eq;
        if (*eq != '=') continue;
        *eq = '\0';
        const char* key = entry;
        const char* value = eq + 1;

        bool match;
        if (key[0] == '*') {
            if (!wildcard) continue;
            const size_t suffix_len = strlen(key + 1);
            match = suffix_len > 0 && name_len >= suffix_len &&
                    strcmp(name + name_len - suffix_len, key + 1) == 0;
        } else {
            if (wildcard) continue;
            match = strcmp(key, name) == 0;
        }
        if (!match) continue;
        strcpy(buffer, value);
        return buffer;
    }
    return nullptr;
}

static bool is_pif_fingerprint_name(const char* name) {
    return strcmp(name, "ro.build.fingerprint") == 0 ||
           (strncmp(name, "ro.", 3) == 0 && has_prop_suffix(name, ".build.fingerprint"));
}

static bool is_pif_build_version_name(const char* name, bool* is_release) {
    if (strncmp(name, "ro.", 3) != 0) return false;
    if (has_prop_suffix(name, ".version.release") ||
        has_prop_suffix(name, ".version.release_or_codename")) {
        *is_release = true;
        return true;
    }
    if (has_prop_suffix(name, ".version.incremental")) {
        *is_release = false;
        return true;
    }
    return false;
}

static bool is_pif_derived_name(const char* name) {
    bool is_release = false;
    return is_pif_fingerprint_name(name) || is_pif_build_version_name(name, &is_release);
}

struct PifDescription {
    char product[PROP_VALUE_MAX];
    char release[PROP_VALUE_MAX];
    char id[PROP_VALUE_MAX];
    char incremental[PROP_VALUE_MAX];
    char type[PROP_VALUE_MAX];
    char tags[PROP_VALUE_MAX];
    bool valid;
};

static bool copy_pif_field(char* dst, const char* src) {
    size_t len = strlen(src);
    if (len >= PROP_VALUE_MAX) return false;
    memcpy(dst, src, len + 1);
    return true;
}

// AxSpoofManager stages the stock build description as
// "product-type release id incremental tags". The fingerprint adds the brand,
// product and device from the staged product identity to the same fields.
static PifDescription read_pif_description() {
    PifDescription d = {};
    char description[PROP_VALUE_MAX];
    if (__system_property_get("persist.sys.pif.build.description", description) <= 0) return d;

    char* tokens[5] = {};
    int count = 0;
    char* p = description;
    while (*p && count < 5) {
        while (*p == ' ') ++p;
        if (*p == '\0') break;
        tokens[count++] = p;
        while (*p && *p != ' ') ++p;
        if (*p) *p++ = '\0';
    }
    if (count < 5) return d;

    char* dash = strrchr(tokens[0], '-');
    if (!dash || dash == tokens[0] || dash[1] == '\0') return d;
    *dash = '\0';

    if (!copy_pif_field(d.product, tokens[0]) ||
        !copy_pif_field(d.release, tokens[1]) ||
        !copy_pif_field(d.id, tokens[2]) ||
        !copy_pif_field(d.incremental, tokens[3]) ||
        !copy_pif_field(d.type, dash + 1) ||
        !copy_pif_field(d.tags, tokens[4])) {
        return d;
    }
    d.valid = true;
    return d;
}

static const char* pif_derived_override(const char* name, char* buffer) {
    bool is_release = false;
    const bool version = is_pif_build_version_name(name, &is_release);
    const bool fingerprint = is_pif_fingerprint_name(name);
    if (!version && !fingerprint) return nullptr;

    PifDescription d = read_pif_description();
    if (!d.valid) return nullptr;

    if (version) {
        const char* value = is_release ? d.release : d.incremental;
        if (*value == '\0' || strlen(value) >= PROP_VALUE_MAX) return nullptr;
        strcpy(buffer, value);
        return buffer;
    }

    char brand[PROP_VALUE_MAX];
    char product[PROP_VALUE_MAX];
    char device[PROP_VALUE_MAX];
    char id[PROP_VALUE_MAX];
    char type[PROP_VALUE_MAX];
    char tags[PROP_VALUE_MAX];
    if (__system_property_get("persist.sys.pif.product.brand", brand) <= 0 ||
        __system_property_get("persist.sys.pif.product.device", device) <= 0 ||
        *brand == '\0' || *device == '\0') {
        return nullptr;
    }
    if (__system_property_get("persist.sys.pif.product.name", product) <= 0 || *product == '\0') {
        if (!copy_pif_field(product, d.product)) return nullptr;
    }

    if (__system_property_get("persist.sys.pif.build.id", id) <= 0 || *id == '\0') {
        if (!copy_pif_field(id, d.id)) return nullptr;
    }
    if (__system_property_get("persist.sys.pif.build.type", type) <= 0 || *type == '\0') {
        if (!copy_pif_field(type, d.type)) return nullptr;
    }
    if (__system_property_get("persist.sys.pif.build.tags", tags) <= 0 || *tags == '\0') {
        if (!copy_pif_field(tags, d.tags)) return nullptr;
    }
    if (*d.release == '\0' || *d.incremental == '\0' || *id == '\0' ||
        *type == '\0' || *tags == '\0') {
        return nullptr;
    }

    int n = snprintf(buffer, PROP_VALUE_MAX, "%s/%s/%s:%s/%s/%s:%s/%s",
                     brand, product, device, d.release, id, d.incremental, type, tags);
    if (n <= 0 || n >= PROP_VALUE_MAX) return nullptr;
    return buffer;
}

static bool is_dynamic_or_derived_prop(const char* name) {
    if (is_pif_derived_name(name)) return true;
    for (const DynamicPropOverride* o = kDynamicProductProps; o->name; ++o) {
        if (strcmp(name, o->name) == 0) return true;
    }
    if (find_product_partition_staging(name)) return true;
    return find_dynamic_suffix_override(name) != nullptr;
}

bool custom_rom_hide_should_spoof_prop(const char* name, char* value) {
    if (!name || !value) return false;
    if (reinterpret_cast<uintptr_t>(name) < 0x1000000) return false;
    if (reinterpret_cast<uintptr_t>(value) < 0x1000000) return false;
    if (!is_app_process()) return false;
    if (is_hidden_staging_prop(name)) { value[0] = '\0'; return true; }
    if (is_hidden_droidguard_prop(name)) {
        // A configured PIF entry still wins over the fallback empty value.
        if (const char* v = find_custom_prop_override(name, value, false)) return true;
        if (const char* v = find_custom_prop_override(name, value, true)) return true;
        value[0] = '\0';
        return true;
    }
    // These keys are hidden from find/foreach; keep the direct read path in
    // sync by serving an empty value instead of a configured PIF entry.
    for (const char* const* p = kSpoofedEmptyProps; *p; ++p) {
        if (strcmp(name, *p) == 0) { value[0] = '\0'; return true; }
    }
    // Apply arbitrary PIF jsonProps to the direct get/read path too. The
    // callback and serial paths already do this through get_prop_override().
    if (is_droidguard_process()) {
        if (const char* v = find_custom_prop_override(name, value, false)) return true;
        if (const char* v = find_custom_prop_override(name, value, true)) return true;
        if (is_rom_identity_prop_name(name)) { value[0] = '\0'; return true; }
    }
    // The fixed DroidGuard table also applies to the direct get path.
    if (const char* override_value = find_droidguard_value_override(name)) {
        if (is_droidguard_process()) {
            strcpy(value, override_value);
            return true;
        }
    }
    for (const PropOverride* o = kSpoofedValueProps; o->name; ++o) {
        if (strcmp(name, o->name) == 0) { strcpy(value, o->value); return true; }
    }
    // PIF build fields are also read through __system_property_get/read, not
    // only through callbacks. Keep those direct paths consistent with the
    // callback and build.prop paths without scanning every property name.
    if (is_droidguard_process() && is_dynamic_or_derived_prop(name)) {
        if (const char* override_value = custom_rom_hide_get_prop_override(name, value)) {
            return true;
        }
    }
    return false;
}

bool custom_rom_hide_should_hide_prop(const char* name) {
    if (!name || reinterpret_cast<uintptr_t>(name) < 0x1000000) return false;
    if (!is_app_process()) return false;
    if (is_hidden_staging_prop(name)) return true;
    if (is_hidden_droidguard_prop(name)) {
        // Keep a configured PIF value visible so find/foreach and callbacks
        // agree with the direct get path; otherwise hide the key completely.
        char buffer[PROP_VALUE_MAX];
        if (find_custom_prop_override(name, buffer, false)) return false;
        return find_custom_prop_override(name, buffer, true) == nullptr;
    }
    for (const char* const* p = kSpoofedEmptyProps; *p; ++p) {
        if (strcmp(name, *p) == 0) return true;
    }
    if (is_droidguard_process() && is_rom_identity_prop_name(name)) {
        char buffer[PROP_VALUE_MAX];
        if (find_custom_prop_override(name, buffer, false)) return false;
        return find_custom_prop_override(name, buffer, true) == nullptr;
    }
    return false;
}

const char* custom_rom_hide_get_prop_override(const char* name, char* buffer) {
    if (!name || reinterpret_cast<uintptr_t>(name) < 0x1000000) return nullptr;
    if (!is_app_process()) return nullptr;
    // is_droidguard_process() is cached per pid once the process name is final.
    const bool droidguard = is_droidguard_process();
    // An exact entry from the PIF config wins over everything below, as in PIFork.
    if (droidguard) {
        if (const char* v = find_custom_prop_override(name, buffer, false)) return v;
        if (is_hidden_droidguard_prop(name)) {
            if (const char* v = find_custom_prop_override(name, buffer, true)) return v;
        }
        if (is_pif_derived_name(name)) {
            if (const char* v = find_custom_prop_override(name, buffer, true)) return v;
            if (const char* v = pif_derived_override(name, buffer)) return v;
        }
        // PIF jsonProps wildcards are part of the configured identity; they
        // must win over the fixed/dynamic fallbacks so a direct read, callback,
        // serial lookup and build.prop rewrite all agree.
        if (const char* v = find_custom_prop_override(name, buffer, true)) return v;
    }
    for (const PropOverride* o = kSpoofedValueProps; o->name; ++o) {
        if (strcmp(name, o->name) == 0) return o->value;
    }
    for (const DynamicPropOverride* o = kDynamicProductProps; o->name; ++o) {
        if (strcmp(name, o->name) == 0) {
            if (!droidguard) return nullptr;
            // This code is also linked into the loader, which cannot contain ELF TLS.
            // The caller owns a PROP_VALUE_MAX buffer for the duration of the read.
            int len = __system_property_get(o->staging_name, buffer);
            if (len > 0) return buffer;
            return nullptr; // staging prop unset — leave the real value alone
        }
    }
    if (const char* staging = find_product_partition_staging(name)) {
        if (!droidguard) return nullptr;
        int len = __system_property_get(staging, buffer);
        if (len > 0) return buffer;
        return nullptr;
    }
    if (const DynamicSuffixOverride* o = find_dynamic_suffix_override(name)) {
        if (!droidguard) return nullptr;
        int len = __system_property_get(o->staging_name, buffer);
        if (len > 0) return buffer;
    }
    if (const char* override_value = find_droidguard_value_override(name)) {
        return droidguard ? override_value : nullptr;
    }
    return nullptr;
}

bool custom_rom_hide_is_app_process() {
    return is_app_process();
}

bool custom_rom_hide_is_droidguard_process() {
    return is_droidguard_process();
}

static const PartitionDevEntry* find_partition_entry_at(int dirfd, const char* path) {
    if (!path) return nullptr;

    const char* lookup_path = path;
    int lookup_dirfd = dirfd;
    char alias[512];
    if (custom_rom_hide_resolve_proc_fd_path(path, alias, sizeof(alias))) {
        lookup_path = alias;
        lookup_dirfd = AT_FDCWD;
    }

    char resolved[512];
    if (!resolve_path_at(lookup_dirfd, lookup_path, resolved, sizeof(resolved))) return nullptr;

    const PartitionDevEntry* best = nullptr;
    size_t best_len = 0;
    for (const PartitionDevEntry* e = kPartitionDmMap; e->path; ++e) {
        size_t len = strlen(e->path);
        if (len <= best_len) continue;
        if (strncmp(resolved, e->path, len) != 0) continue;
        if (resolved[len] != '\0' && resolved[len] != '/') continue;
        best = e;
        best_len = len;
    }
    return best;
}

static void normalize_statfs_type(struct statfs* sf) {
    if (sf->f_type == static_cast<decltype(sf->f_type)>(OVERLAYFS_SUPER_MAGIC)) {
        sf->f_type = static_cast<decltype(sf->f_type)>(EROFS_SUPER_MAGIC_V1);
    }
}

void custom_rom_hide_spoof_stat_at(int dirfd, const char* path, struct stat* sb) {
    if (!is_app_process() || !path || !sb) return;
    const PartitionDevEntry* e = find_partition_entry_at(dirfd, path);
    if (e && major(sb->st_dev) != DM_MAJOR) sb->st_dev = makedev(DM_MAJOR, e->dm_minor);
}

void custom_rom_hide_spoof_stat(const char* path, struct stat* sb) {
    custom_rom_hide_spoof_stat_at(AT_FDCWD, path, sb);
}

void custom_rom_hide_spoof_statx_at(int dirfd, const char* path, struct statx* sx) {
    if (!is_app_process() || !path || !sx) return;
    const PartitionDevEntry* e = find_partition_entry_at(dirfd, path);
    if (e && sx->stx_dev_major != DM_MAJOR) {
        sx->stx_dev_major = DM_MAJOR;
        sx->stx_dev_minor = e->dm_minor;
    }
}

void custom_rom_hide_spoof_statx(const char* path, struct statx* sx) {
    custom_rom_hide_spoof_statx_at(AT_FDCWD, path, sx);
}

void custom_rom_hide_spoof_statfs(const char* path, struct statfs* sf) {
    if (!is_app_process() || !path || !sf) return;
    normalize_statfs_type(sf);
}

void custom_rom_hide_spoof_fd_stat(int fd, struct stat* sb) {
    if (fd < 0 || !sb) return;
    if (!is_app_process()) return;

    int saved_errno = errno;
    if (is_tracked_fd(fd)) {
        // resolve_encoded_memfd_path gates on the memfd link still decoding, so a stale
        // tracking bit on a reused fd number self-heals instead of reporting old metadata.
        char real_path[512];
        if (resolve_encoded_memfd_path(fd, real_path, sizeof(real_path))) {
            // The live path is exact when it still resolves; the captured record covers
            // the case where the task it named has gone.
            struct stat real_sb;
            FdMeta meta;
            if (raw_fstatat(AT_FDCWD, real_path, &real_sb, 0) == 0) *sb = real_sb;
            else if (load_fd_meta(fd, &meta) && meta.sb_ok) *sb = meta.sb;
        }
    } else if (major(sb->st_dev) != DM_MAJOR) {
        char fd_path[512];
        if (resolve_fd_path(fd, fd_path, sizeof(fd_path))) {
            custom_rom_hide_spoof_stat(fd_path, sb);
        }
    }
    errno = saved_errno;
}

void custom_rom_hide_spoof_fd_statx(int fd, unsigned mask, struct statx* sx) {
    if (fd < 0 || !sx) return;
    if (!is_app_process()) return;

    int saved_errno = errno;
    if (is_tracked_fd(fd)) {
        char real_path[512];
        if (resolve_encoded_memfd_path(fd, real_path, sizeof(real_path))) {
            // The live path honors the caller's mask exactly; the captured record is
            // the fallback for when the task it named has gone.
            struct statx real_sx;
            FdMeta meta;
            if (raw_statx(AT_FDCWD, real_path, 0, mask, &real_sx) == 0) *sx = real_sx;
            else if (load_fd_meta(fd, &meta) && meta.sx_ok) *sx = meta.sx;
        }
    } else if (sx->stx_dev_major != DM_MAJOR) {
        char fd_path[512];
        if (resolve_fd_path(fd, fd_path, sizeof(fd_path))) {
            custom_rom_hide_spoof_statx(fd_path, sx);
        }
    }
    errno = saved_errno;
}

void custom_rom_hide_spoof_fd_statfs(int fd, struct statfs* sf) {
    if (fd < 0 || !sf) return;
    if (!is_app_process()) return;

    int saved_errno = errno;
    if (is_tracked_fd(fd)) {
        char real_path[512];
        if (resolve_encoded_memfd_path(fd, real_path, sizeof(real_path))) {
            struct statfs real_sf;
            if (raw_statfs(real_path, &real_sf) == 0) {
                *sf = real_sf;
            } else {
                sf->f_type = PROC_SUPER_MAGIC;
            }
        }
    }
    normalize_statfs_type(sf);
    errno = saved_errno;
}
