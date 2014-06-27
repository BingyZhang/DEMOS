#!/bin/sh
cd /var/www/finer/EC-ElGamal/
echo "$1" > EC_cipher.txt
echo "$2" > EC_plain.txt
./Add
./AddEC
./Verify
