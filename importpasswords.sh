#!/bin/bash

apt -y install aria2 p7zip-full
aria2c -o jdk17.tar.gz https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.1%2B12/OpenJDK17U-jdk_x64_linux_hotspot_17.0.1_12.tar.gz
tar xzf jdk17.tar.gz
rm jdk17.tar.gz
mv jdk-17.0.1+12 jdk17
aria2c --seed-time=0 https://downloads.pwnedpasswords.com/passwords/pwned-passwords-sha1-ordered-by-hash-v8.7z.torrent
rm pwned-passwords-sha1-ordered-by-hash-v8.7z.torrent

7z x pwned-passwords-sha1-ordered-by-hash-v8.7z
rm pwned-passwords-sha1-ordered-by-hash-v8.7z

aria2c https://github.com/ralscha/selfhost-hibp-passwords/releases/download/query-1.0.0/hibp-passwords-importer.jar
jdk17/bin/java -jar hibp-passwords-importer.jar import pwned-passwords-sha1-ordered-by-hash-v8.txt hibp-passwords

rm pwned-passwords-sha1-ordered-by-hash-v8.txt
rm -fr selfhost-hibp-passwords