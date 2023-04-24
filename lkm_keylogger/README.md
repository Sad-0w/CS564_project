# Keylog

A stealthy Linux kernel-based keylogger that hides itself from `lsmod` and
`/proc/modules`. Also can also hide TCP ports.

## Usage
This rootkit is in the form of a loadable kernel module. It receives keyboard
events from the kernel and outputs to a character device. Install using
`insmod`:

```console
$ insmod keylog
$ dmesg | tail -n1
[  498.484687] keylog: Registered device major number 249
$ mknod chrdev0 c 249 0  # create a character device, 249 is the major no.
$ cat chrdev0
dmesg | tail -n1
mknod chrdev0 c 249 0
cat chrdev0
```

## Build
Make sure you have `linux-headers` installed. Also requires gcc, 

```console
$ make
```

To hide the module from kernel use *(STILL IN TESTING)

```console
$ make HIDDEN=''
```

## Development
Requires a VM to run, ssh into a vagrant VM has some issues as the input may not be read (depending on the setup)

## References

[Lamcw's keylog](https://github.com/lamcw/keylog) \\
[Xcellerator's kernel hacking tutorials](https://github.com/xcellerator/linux_kernel_hacking) \\
[Jarun's keylogger](https://github.com/jarun/spy) \\
[bones-codes keylogger](https://github.com/bones-codes/the_colonel) \\
