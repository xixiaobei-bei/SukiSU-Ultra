// SPDX-License-Identifier: GPL-2.0
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <generated/utsrelease.h>
#include <generated/compile.h>
#include <linux/version.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#endif
#include <linux/sched.h>

#include "kernel_includes.h"

// uapi
#include "include/uapi/app_profile.h"
#include "include/uapi/feature.h"
#include "include/uapi/selinux.h"
#include "include/uapi/supercall.h"
#include "include/uapi/sulog.h"

// includes
#include "include/klog.h"
#include "include/ksu.h"

// kernel compat, lite ones
#include "infra/kernel_compat.h"

#include "policy/app_profile.h"
#include "policy/allowlist.h"
#include "policy/feature.h"
#include "manager/apk_sign.h"
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"
#include "manager/pkg_observer.h"
#include "supercall/internal.h"
#include "supercall/supercall.h"
#include "infra/su_mount_ns.h"
#include "infra/file_wrapper.h"
#include "infra/event_queue.h"
#include "feature/kernel_umount.h"
#include "feature/sucompat.h"
#include "feature/sulog.h"
#include "runtime/ksud.h"
#include "sulog/event.h"
#include "sulog/fd.h"

#include "selinux/selinux.h"
#include "selinux/sepolicy.h"

// selinux includes
#include "avc_ss.h"
#include "objsec.h"
#include "ss/services.h"
#include "ss/symtab.h"
#include "xfrm.h"
#ifndef KSU_COMPAT_USE_SELINUX_STATE
#include "avc.h"
#endif

#ifdef CONFIG_KSU_MANUAL_SU
#include "other/manual_su.h"
#endif

#ifdef CONFIG_KPM
#include "kpm/kpm.h"
#include "kpm/compact.h"
#include "kpm/super_access.h"
#endif

#ifdef KSU_TP_HOOK
#include "syscall_hook_manager.h"
#include "hook/syscall_hook.h"
#elif defined(CONFIG_KSU_MANUAL_HOOK)
#include "hook/lsm_hook.h"
#endif

struct cred *ksu_cred;

bool allow_shell = IS_ENABLED(CONFIG_KSU_DEBUG);
module_param(allow_shell, bool, 0);

bool ksu_late_loaded;
static bool ksu_boot_completed;

extern void ksu_feature_init(void);
extern void ksu_supercalls_init(void);
extern void ksu_supercalls_exit(void);
extern void ksu_allowlist_init(void);
extern void ksu_allowlist_exit(void);
extern void ksu_load_allow_list(void);
extern void ksu_throne_tracker_init(void);
extern void ksu_throne_tracker_exit(void);
extern void ksu_observer_init(void);
extern void ksu_observer_exit(void);
extern void ksu_file_wrapper_init(void);
extern void ksu_file_wrapper_exit(void);
extern void ksu_ksud_init(void);
extern void ksu_ksud_exit(void);
extern void ksu_sulog_init(void);
extern void ksu_sulog_exit(void);
extern void ksu_kernel_umount_init(void);
extern void ksu_kernel_umount_exit(void);
extern void ksu_sucompat_init(void);
extern void ksu_sucompat_exit(void);
extern void ksu_setuid_hook_init(void);
extern void ksu_setuid_hook_exit(void);
extern void apply_kernelsu_rules(void);
extern void cache_sid(void);
extern void setup_ksu_cred(void);
extern void escape_to_root_for_init(void);
extern void track_throne(bool, bool);
extern bool getenforce(void);
extern void setenforce(bool);
extern void ksu_dynamic_manager_init(void);
extern void ksu_dynamic_manager_exit(void);

static inline void ksu_hook_init(void)
{
#if defined(KSU_TP_HOOK)
    ksu_syscall_hook_init();
    ksu_syscall_hook_manager_init();
#elif defined(CONFIG_KSU_MANUAL_HOOK)
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0)
    ksu_lsm_hook_init();
#endif
#elif defined(CONFIG_KSU_SUSFS)
    susfs_init();
#else
#error "Unsupported hook type"
#endif
}

static inline void ksu_hook_exit(void)
{
#if defined(KSU_TP_HOOK)
    ksu_syscall_hook_manager_exit();
#else
    ksu_sucompat_exit();
    ksu_setuid_hook_exit();
#endif
}

#if defined(CONFIG_STACKPROTECTOR) &&                                                                                  \
    (defined(CONFIG_ARM64) && defined(MODULE) && !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void ksu_setup_stack_chk_guard()
{
    unsigned long canary;

    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelsu_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl ksu_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

int __init kernelsu_init(void)
{
    pr_info("Initialized on: %s (%s) with driver version: %u\n", UTS_RELEASE, UTS_MACHINE, KSU_VERSION);
#ifdef MODULE
    ksu_late_loaded = (current->pid != 1);
#else
    ksu_late_loaded = false;
#endif

#if defined(KSU_TP_HOOK) && defined(__x86_64__)
    if (!boot_cpu_has(X86_FEATURE_INDIRECT_SAFE)) {
        pr_alert("*************************************************************");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("**                                                         **");
        pr_alert("**        X86_FEATURE_INDIRECT_SAFE is not enabled!        **");
        pr_alert("**      KernelSU will abort initialization to prevent      **");
        pr_alert("**                     kernel panic.                       **");
        pr_alert("**                                                         **");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("*************************************************************");
        return -ENOSYS;
    }
#endif

#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif

    if (allow_shell) {
        pr_alert("shell is allowed at init!");
    }

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
    }

    ksu_feature_init();

    ksu_supercalls_init();

    ksu_setuid_hook_init();
    ksu_sucompat_init();

    if (ksu_late_loaded) {
        pr_info("late load mode, skipping kprobe hooks\n");

        apply_kernelsu_rules();
        cache_sid();
        setup_ksu_cred();
        escape_to_root_for_init();

        ksu_allowlist_init();
        ksu_load_allow_list();

        ksu_hook_init();

        ksu_throne_tracker_init();
        ksu_observer_init();
        ksu_file_wrapper_init();

        ksu_sulog_init();
        ksu_dynamic_manager_init();

        ksu_boot_completed = true;
        track_throne(false, true);

        if (!getenforce()) {
            pr_info("Permissive SELinux, enforcing\n");
            setenforce(true);
        }
    } else {
        ksu_hook_init();

        ksu_allowlist_init();

        ksu_throne_tracker_init();

        ksu_ksud_init();

        ksu_file_wrapper_init();
    }

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
    return 0;
}

void __exit kernelsu_exit(void)
{
    ksu_hook_exit();
    ksu_supercalls_exit();
    if (!ksu_late_loaded)
        ksu_ksud_exit();
    ksu_dynamic_manager_exit();
    ksu_sulog_exit();

    synchronize_rcu();
    ksu_observer_exit();
    ksu_throne_tracker_exit();
    ksu_allowlist_exit();
    ksu_file_wrapper_exit();
    ksu_feature_exit();
    ksu_kernel_umount_exit();
    ksu_sucompat_exit();
    ksu_setuid_hook_exit();

    if (ksu_cred) {
        put_cred(ksu_cred);
    }
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelsu_init_early);
#else
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
#endif