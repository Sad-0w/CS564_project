# CVE-2022-0847 -  Dirty Pipe Local Privilege Escalation Vulnerability
This is a script for privilege escalation
It works with Linux Kernels 5.8 < 5.16.11
It modifies the read-only file /etc/passwd
It changes the fist line in /etc/passwd to add a new user "rootz" with root privileges

# Credits
https://github.com/bbaranoff/CVE-2022-0847
https://www.exploit-db.com/exploits/50808
https://vk9-sec.com/dirty-pipe-linux-kernel-privilege-escalation-cve-2022-0847/