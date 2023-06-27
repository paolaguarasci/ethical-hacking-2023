# SHA1
```shell
$ hashcat -m 100 SHA1_hashes /usr/share/wordlists/rockyou.txt
```
# linux password

```shell
$ echo nix_hash
root:$6$tOA0cyybhb/Hr7DN$htr2vffCWiPGnyFOicJiXJVMbk1muPORR.eRGYfBYUnNPUjWABGPFiphjIjJC5xPfFUASIbVKDAHS3vTW1qU.1:18285:0:99999:7:::
$ hashcat -m 1800 nix_hash /usr/share/wordlists/rockyou.txt
```

# nota sugli hash seguenti (ntlm, ntlmv2 e samdb)
Credential theft and password re-use are widespread tactics during assessments against organizations using Active Directory to manage their environment. It is often possible to obtain credentials in cleartext or re-use password hashes to further access via Pass-the-Hash or SMB Relay attacks. Still, some techniques will result in a password hash that must be cracked offline to further our access. Some examples include a NetNTLMv1 or NetNTLMv2 obtained through a Man-in-the-middle (MITM) attack, a Kerberos 5 TGS-REP hash obtained through a Kerberoasting attack, or an NTLM hash obtained either by dumping credentials from memory using the Mimikatz tool or obtained from a Windows machine's local SAM database.

# NTLM
otttenuto con Pass-the-Hash or SMB Relay attacks
```shell
# con ruleset
$ hashcat -a 6 -m 1000 hash /usr/share/wordlists/rockyou.txt '?d?s'
```

# NetNTLMv2
otttenuto con Pass-the-Hash or SMB Relay attacks
```shell
$ echo inlanefreight_ntlmv2 # ottenuto con responder
sqladmin::INLANEFREIGHT:f54d6f198a7a47d4:7FECABAE13101DAAA20F1B09F7F7A4EA:0101000000000000C0653150DE09D20126F3F71DF13C1FD8000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D201060004000200000008003000300000000000000000000000003000001A67637962F2B7BF297745E6074934196D5F4371B6BA3E796F2997306FD4C1C00A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100390035002E00310037003000000000000000000000000000
$ hashcat -a 0 -m 5600 inlanefreight_ntlmv2 /usr/share/wordlists/rockyou.txt 
```


# Kerberos 5 TGS-REP etype 23

```shell
$ echo kerberos_hash # ottenuto con Kerberoasting attack
$krb5tgs$23$*sql_svc$INLANEFREIGHT.LOCAL$mssql/inlanefreight.local~1443*$80be357f5e68b4f64a185397bf72cf1c$579d028f0f91f5791683844c3a03f48972cb9013eddf11728fc19500679882106538379cbe1cb503677b757bcb56f9e708cd173a5b04ad8fc462fa380ffcb4e1b4feed820fa183109e2653b46faee565af76d5b0ee8460a3e0ad48ea098656584de67974372f4a762daa625fb292556b407c0c97fd629506bd558dede0c950a039e2e3433ee956fc218a54b148d3e5d1f99781ad4e419bc76632e30ea2c1660663ba9866230c790ba166b865d5153c6b85a184fbafd5a4af6d3200d67857da48e20039bbf31853da46215cbbc5ebae6a3b0225b6651ec8cc792c8c3d5893a8d014f9d297ac297288e76d27a1ed2942d6997f6b24198e64fea9ff5a94badd53cc12a73e9505e4dab36e4bd1ef7fe5a08e527d9046b49e730d83d8af395f06fe35d360c59ab8ebe2c3b7553acf8d40c296b86c1fb26fdf43fa8be2ac4a92152181b81afb1f4773936b0ccc696f21e8e0fe7372252b3c24d82038c62027abc34a4204fb6e52bf71290fdf0db60b1888f8369a7917821f6869b6e51bda15f1fd7284ca1c37fb2dc46c367046a15d093cc501f3155f1e63040313cc8db2a8437ee6dc8ceb04bf924427019b396667f0532d995e3d655b9fb0ef8e61b31e523d81914d9eb177529783c29788d486139e1f3d29cbe4d2f881c61f74ff32a9233134ec69f26082e8aaa0c0e99006a5666c24fccfd195796a0be97cecb257259a640641f8c2d58d2d94452ec00ad84078afc1f7f72f3b9e8210b5db73bf70cd13ef172ef3b233c987d5ec7ea12a4d4921a43fb670c9f48aaae9e1d48ec7be58638a8b2f89a62b56775deddbbc971803316470ee416d8a6c0c8d17982396f6c0c0eeec425d5c599fb60b5c39f8e9ceff4ee25c5bc953178972de616edae61586bb868e463f420e9e09c083662bcf6f0f522f78630792e02e6986f5dd042dfb70100ab59d8a01093b3d89949ea19fe9c596a8681e2a71abe75debd62b985d03d488442aa41cc8993eff0224de62221d39be8bf1d8b26f8f8768e90e5b4b886adaf02a19f55e6d1fd11b004d4e7b170c4f7feaa04b8dad207d6f863d50a251d9a9ce66951de41a3690fec6144e73428d4718cc7ec5eeeff841b4329a7ba51624f678557b6eafc55af026314cbf9dd9ca232977da3cce204899f3048101e0010f42d0076cd494526beea862c72ee48749ba071bcdd1a96c64a0d8f48c6acad7730121021be6323f69505aad8fb6281b7ac4a607d1d241f1fbffc70c4a74c997bb2fb77c452c0077efdea2a6c00704a8bee28326b5e554e1faa48a33963ce2c2e0e2446b4504a05d541bbaf531e1644ad92a2feae5b2eb8851b067e7bd8d7d23d82e63d368983ba44f52901cba7e05cfa35e832ec445a7de50eca670fa90
$ hashcat -a 0 -m 13100 kerberos_hash /usr/share/wordlists/rockyou.txt 
```

# MS Cache 2
```shell
$ echo sam_hash # da local SAM database's contents
$DCC2$10240#backup_admin#62dabbde52af53c75f37df260af1008e
$ hashcat -a 0 -m 2100 sam_hash /usr/share/wordlists/rockyou.txt 
```


# zip
```shell
$ zip2john archive.zip > ziphash

# se non funziona usare la versione perl
# $ locate 7z2john.pl
# $ /usr/share/john/7z2john.pl archive.zip > ziphash 

$ hashcat -a 0 -m 17200 ziphash /usr/share/wordlists/rockyou.txt
# attenzione all amodalita
# 11600 	7-Zip
# 13600 	WinZip
# 17200 	PKZIP (Compressed)
# 17210 	PKZIP (Uncompressed)
# 17220 	PKZIP (Compressed Multi-File)
# 17225 	PKZIP (Mixed Multi-File)
# 17230 	PKZIP (Compressed Multi-File Checksum-Only)
# 23001 	SecureZIP AES-128
# 23002 	SecureZIP AES-192
# 23003 	SecureZIP AES-256

```

# keepass

```shell
$ keepass2john Master.kdbx > keepass_hash
$ hashcat -a 0 -m 13400 keepass_hash /usr/share/wordlists/rockyou.txt
# modalita
# 13400 	KeePass 1 AES / without keyfile
# 13400 	KeePass 2 AES / without keyfile
# 13400 	KeePass 1 Twofish / with keyfile
# 13400 	Keepass 2 AES / with keyfile

```

# pdf 

```shell
$ pdf2john protected.pdf | awk -F":" '{ print $2}' > pdf_hash

# nota che -m 10500 vuol dire che e' un pdf 1.4, gli altri sono
# 10400 	PDF 1.1 - 1.3 (Acrobat 2 - 4)
# 10410 	PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1
# 10420 	PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2
# 10500 	PDF 1.4 - 1.6 (Acrobat 5 - 8)
# 10600 	PDF 1.7 Level 3 (Acrobat 9)
# 10700 	PDF 1.7 Level 8 (Acrobat 10 - 11)
$ hashcat -a 0 -m 10500 pdf_hash /usr/share/wordlists/rockyou.txt
```

# wireless - Cracking MIC
git clone https://github.com/hashcat/hashcat-utils.git

```shell
$ git clone https://github.com/hashcat/hashcat-utils.git
$ cd hashcat-utils/src
$ make
$ /opt/hashcat-utils/src/cap2hccapx.bin corp_capture1-01.cap mic_to_crack.hccapx
$ hashcat -a 0 -m 22000 mic_to_crack.hccapx /usr/share/wordlists/rockyou.txt
```

# wireless - Cracking PMKID

```shell
$ git clone https://github.com/ZerBea/hcxtools.git
$ cd hcxtools
$ make
$ sudo make install
$ hcxpcaptool -z pmkidhash_corp cracking_pmkid.cap
$ hashcat -a 0 -m 22000 pmkidhash_corp /usr/share/wordlists/rockyou.txt
```