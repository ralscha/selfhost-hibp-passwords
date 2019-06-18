#!/bin/bash

apt -y install aria2 p7zip-full
aria2c -o jdk12.tar.gz https://github.com/AdoptOpenJDK/openjdk12-binaries/releases/download/jdk-12.0.1%2B12/OpenJDK12U-jdk_x64_linux_hotspot_12.0.1_12.tar.gz
tar xzf jdk12.tar.gz
rm jdk12.tar.gz
mv jdk-12.0.1+12 jdk12
aria2c --seed-time=0 https://downloads.pwnedpasswords.com/passwords/pwned-passwords-sha1-ordered-by-hash-v4.7z.torrent
rm pwned-passwords-sha1-ordered-by-hash-v4.7z.torrent

7z x pwned-passwords-sha1-ordered-by-hash-v4.7z
rm pwned-passwords-sha1-ordered-by-hash-v4.7z

git clone https://github.com/ralscha/selfhost-hibp-passwords.git
cd selfhost-hibp-passwords/importer

JAVA_HOME=../../jdk12 ../mvnw package
mv target/hibp-passwords-importer.jar ../..
cd ../..
jdk12/bin/java -jar hibp-passwords-importer.jar import pwned-passwords-sha1-ordered-by-hash-v4.txt hibp-passwords

rm pwned-passwords-sha1-ordered-by-hash-v4.txt
rm -fr selfhost-hibp-passwords