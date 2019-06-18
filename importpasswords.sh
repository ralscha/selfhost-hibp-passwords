#!/bin/bash

apt -y install aria2 p7zip-full
aria2c -o jre12.tar.gz https://github.com/AdoptOpenJDK/openjdk12-binaries/releases/download/jdk-12.0.1%2B12/OpenJDK12U-jre_x64_linux_hotspot_12.0.1_12.tar.gz
tar xzf jre12.tar.gz
rm jre12.tar.gz
mv jdk-12.0.1+12-jre jre12
aria2c --seed-time=0 https://downloads.pwnedpasswords.com/passwords/pwned-passwords-sha1-ordered-by-hash-v4.7z.torrent
rm pwned-passwords-sha1-ordered-by-hash-v4.7z.torrent

7z x pwned-passwords-sha1-ordered-by-hash-v4.7z
rm pwned-passwords-sha1-ordered-by-hash-v4.7z

aria2c https://github.com/ralscha/selfhost-hibp-passwords/releases/download/query-1.0.0/hibp-passwords-importer.jar
jre12/bin/java -jar hibp-passwords-importer.jar import pwned-passwords-sha1-ordered-by-hash-v4.txt hibp-passwords

rm pwned-passwords-sha1-ordered-by-hash-v4.txt
rm -fr selfhost-hibp-passwords