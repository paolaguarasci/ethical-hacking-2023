# Introduzione 

I buffer overflow sono diventati meno comuni nel mondo d'oggi, poiché i compilatori moderni hanno integrato protezioni di memoria che rendono difficile che si verifichino accidentalmente bug di corruzione della memoria. Detto questo, linguaggi come il C non scompariranno presto e sono predominanti nel software embedded e nell'IOT (Internet of Things). Uno dei miei preferiti tra i Buffer Overflow più recenti è stato CVE-2021-3156, un Buffer Overflow basato su Heap in sudo.

Questi attacchi non si limitano ai file binari, ma un gran numero di buffer overflow si verifica nelle applicazioni web, in particolare nei dispositivi embedded che utilizzano server web personalizzati. Un buon esempio è CVE-2017-12542 con i dispositivi di gestione HP iLO (Integrated Lights Out). Il semplice invio di 29 caratteri in un parametro dell'intestazione HTTP ha causato un buffer overflow che ha bypassato il login. Mi piace questo esempio perché non c'è bisogno di un payload vero e proprio, di cui si parlerà più avanti, dato che il sistema "fallisce l'apertura" quando si verifica un errore.

In breve, i buffer overflow sono causati da un codice di programma errato, che non è in grado di elaborare correttamente quantità di dati troppo grandi da parte della CPU e può, quindi, manipolare l'elaborazione della CPU. Supponiamo, ad esempio, che vengano scritti troppi dati in un buffer di memoria riservato o in uno stack non limitato. In questo caso, registri specifici verranno sovrascritti, consentendo l'esecuzione di codice.

Un buffer overflow può causare l'arresto del programma, corrompere i dati o danneggiare le strutture di dati nel runtime del programma. Quest'ultimo può sovrascrivere l'indirizzo di ritorno del programma specifico con dati arbitrari, consentendo a un aggressore di eseguire comandi con i privilegi del processo vulnerabile all'overflow del buffer passando codice macchina arbitrario. Questo codice è solitamente destinato a fornire un accesso più comodo al sistema per utilizzarlo per i propri scopi. Tali buffer overflow sono comuni nei server e i worm di Internet sfruttano anche il software client.

Un obiettivo particolarmente popolare nei sistemi Unix è l'accesso root, che ci dà tutti i permessi per accedere al sistema. Tuttavia, come spesso viene frainteso, questo non significa che un buffer overflow che porta "solo" ai privilegi di un utente standard sia innocuo. Ottenere l'agognato accesso root è spesso molto più facile se si dispone già dei privilegi di utente.

I buffer overflow, oltre alla negligenza della programmazione, sono resi possibili soprattutto dai sistemi informatici basati sull'architettura Von-Neumann.

La causa più significativa dei buffer overflow è l'uso di linguaggi di programmazione che non monitorano automaticamente i limiti del buffer di memoria o della pila per evitare il buffer overflow (basato sulla pila). Questi includono i linguaggi C e C++, che enfatizzano le prestazioni e non richiedono il monitoraggio.

Per questo motivo, gli sviluppatori sono costretti a definire da soli tali aree nel codice di programmazione, il che aumenta la vulnerabilità di molte volte. Spesso queste aree vengono lasciate indefinite a scopo di test o per negligenza. Anche se sono state utilizzate a scopo di test, potrebbero essere state trascurate alla fine del processo di sviluppo.

Tuttavia, non tutti gli ambienti applicativi possono presentare una condizione di buffer overflow. Ad esempio, un'applicazione Java stand-alone è meno probabile rispetto ad altre per via del modo in cui Java gestisce la memoria. Java utilizza una tecnica di "garbage collection" per gestire la memoria, che aiuta a prevenire le condizioni di buffer overflow.

Lo sviluppo dell'exploit avviene nella fase di exploit dopo che sono stati identificati il software specifico e le sue versioni. L'obiettivo della fase di exploit è quello di utilizzare le informazioni trovate e la loro analisi per sfruttare le potenziali modalità di interazione e/o accesso al sistema target.

Sviluppare i propri exploit può essere molto complesso e richiede una profonda conoscenza delle operazioni della CPU e delle funzioni del software che funge da bersaglio. Molti exploit sono scritti in diversi linguaggi di programmazione. Uno dei linguaggi di programmazione più popolari è Python, perché è facile da capire e da scrivere. In questo modulo ci concentreremo sulle tecniche di base per lo sviluppo di exploit, poiché è necessario sviluppare una comprensione fondamentale prima di poter affrontare i vari meccanismi di sicurezza della memoria.

Prima di eseguire qualsiasi exploit, dobbiamo capire cos'è un exploit. Un exploit è un codice che fa sì che il servizio esegua un'operazione desiderata abusando della vulnerabilità trovata. Tali codici servono spesso come proof-of-concept (POC) nei nostri rapporti.

Esistono due tipi di exploit. Uno è sconosciuto (0-day exploit) e l'altro è noto (N-day exploit).
Exploit 0-day
Un exploit 0-day è un codice che sfrutta una vulnerabilità appena identificata in un'applicazione specifica. Non è necessario che la vulnerabilità sia pubblica nell'applicazione. Il pericolo di questi exploit è che se gli sviluppatori dell'applicazione non sono informati della vulnerabilità, è probabile che persistano con nuovi aggiornamenti.
Sfruttamenti N-Day

Se la vulnerabilità viene pubblicata e informa gli sviluppatori, questi ultimi avranno comunque bisogno di tempo per scrivere una correzione che li prevenga il prima possibile. Quando vengono pubblicati, si parla di N-day exploit, contando i giorni che intercorrono tra la pubblicazione dell'exploit e un attacco ai sistemi non patchati.

Inoltre, questi exploit possono essere suddivisi in quattro diverse categorie:

    Locale
    Remoto
    DoS
    WebApp

Exploit locali

Gli exploit locali / exploit di escalation dei privilegi possono essere eseguiti quando si apre un file. Tuttavia, il prerequisito è che il software locale contenga una vulnerabilità di sicurezza. Spesso un exploit locale (ad esempio, in un documento PDF o come macro in un file Word o Excel) cerca innanzitutto di sfruttare le falle di sicurezza nel programma con cui il file è stato importato per ottenere un livello di privilegio più elevato e quindi caricare ed eseguire codice dannoso / shellcode nel sistema operativo. L'azione effettiva che l'exploit esegue è chiamata payload.
Exploit remoti
Gli exploit remoti sfruttano molto spesso la vulnerabilità di overflow del buffer per ottenere il payload in esecuzione sul sistema. Questo tipo di exploit si differenzia dagli exploit locali perché può essere eseguito attraverso la rete per eseguire l'operazione desiderata.
Sfruttamenti DoS

Gli exploit DoS (Denial of Service) sono codici che impediscono il funzionamento di altri sistemi, ovvero causano il crash di singoli software o dell'intero sistema.
Exploit di applicazioni Web

Un exploit di un'applicazione Web utilizza una vulnerabilità di tale software. Tali vulnerabilità possono, ad esempio, consentire l'iniezione di comandi nell'applicazione stessa o nel database sottostante.

L'architettura del Von-Neumann è stata sviluppata dal matematico ungherese John von Neumann ed è composta da quattro unità funzionali:

    Memoria
    Unità di controllo
    Unità logica aritmetica
    Unità di ingresso/uscita

Nell'architettura di Von-Neumann, le unità più importanti, l'Unità Logico Aritmetica (ALU) e l'Unità di Controllo (CU), sono combinate nella vera e propria Unità di Elaborazione Centrale (CPU). La CPU è responsabile dell'esecuzione delle istruzioni e del controllo del flusso. Le istruzioni vengono eseguite una dopo l'altra, passo dopo passo. I comandi e i dati vengono prelevati dalla memoria dalla CU. Il collegamento tra processore, memoria e unità di input/output è chiamato sistema di bus, che non è menzionato nell'architettura originale di Von-Neumann ma svolge un ruolo essenziale nella pratica. Nell'architettura di Von-Neumann, tutte le istruzioni e i dati vengono trasferiti attraverso il sistema bus.

![](img/von_neumann3.png)

La memoria può essere suddivisa in due diverse categorie:

    Memoria primaria
    Memoria secondaria

Memoria primaria

La memoria primaria è la cache e la memoria ad accesso casuale (RAM). Se ci pensiamo logicamente, la memoria non è altro che un luogo dove immagazzinare informazioni. Possiamo pensare che sia come lasciare qualcosa a uno dei nostri amici per riprenderlo più tardi. A tal fine, però, è necessario conoscere l'indirizzo dell'amico per riprendere ciò che abbiamo lasciato. È la stessa cosa della RAM. La RAM descrive un tipo di memoria le cui allocazioni di memoria sono accessibili direttamente e casualmente tramite i loro indirizzi di memoria.

La cache è integrata nel processore e funge da buffer che, nel migliore dei casi, garantisce che il processore sia sempre alimentato con dati e codice di programma. Prima che il codice di programma e i dati entrino nel processore per l'elaborazione, la RAM funge da memoria dati. La dimensione della RAM determina la quantità di dati che possono essere memorizzati dal processore. Tuttavia, quando la memoria primaria perde l'alimentazione, tutti i contenuti memorizzati vanno persi.
Memoria secondaria
La memoria secondaria è l'archivio dati esterno, come HDD/SSD, unità flash e CD/DVD-ROM di un computer, a cui non si accede direttamente dalla CPU, ma tramite le interfacce di I/O. In altre parole, è un dispositivo di archiviazione di massa. In altre parole, si tratta di un dispositivo di archiviazione di massa. Viene utilizzata per memorizzare in modo permanente i dati che non devono essere elaborati al momento. Rispetto alla memoria primaria, ha una capacità di archiviazione maggiore, può memorizzare i dati in modo permanente anche senza alimentazione e funziona molto più lentamente.

Unità di controllo

L'unità di controllo (CU) è responsabile del corretto funzionamento delle singole parti del processore. Per i compiti dell'unità di controllo viene utilizzato un bus interno. I compiti della CU possono essere riassunti come segue:

    Lettura dei dati dalla RAM
    Salvataggio dei dati nella RAM
    Fornire, decodificare ed eseguire un'istruzione
    Elaborazione degli ingressi dalle periferiche
    Elaborazione delle uscite verso le periferiche
    Controllo delle interruzioni
    Monitoraggio dell'intero sistema

Il CU contiene il registro delle istruzioni (IR), che contiene tutte le istruzioni che il processore decodifica ed esegue di conseguenza. Il decodificatore di istruzioni traduce le istruzioni e le passa all'unità di esecuzione, che le esegue. L'unità di esecuzione trasferisce i dati all'ALU per il calcolo e ne riceve il risultato. I dati utilizzati durante l'esecuzione sono temporaneamente memorizzati in registri.

Unità di elaborazione centrale

L'unità di elaborazione centrale (CPU) è l'unità funzionale di un computer che fornisce l'effettiva potenza di elaborazione. È responsabile dell'elaborazione delle informazioni e del controllo delle operazioni di elaborazione. A tal fine, la CPU recupera i comandi dalla memoria uno dopo l'altro e avvia l'elaborazione dei dati.

Il processore viene spesso chiamato anche microprocessore quando è inserito in un singolo circuito elettronico, come nei nostri PC.

Ogni CPU ha un'architettura su cui è stata costruita. Le architetture di CPU più conosciute sono:

    x86/i386 - (AMD e Intel)
    x86-64/amd64 - (Microsoft e Sun)
    ARM - (Acorn)

Ognuna di queste architetture di CPU è costruita in un modo specifico, chiamato Instruction Set Architecture (ISA), che la CPU utilizza per eseguire i suoi processi. L'ISA, quindi, descrive il comportamento di una CPU in relazione al set di istruzioni utilizzato. I set di istruzioni sono definiti in modo da essere indipendenti da una specifica implementazione. Soprattutto, l'ISA ci dà la possibilità di comprendere il comportamento unificato del codice macchina in linguaggio assembly per quanto riguarda registri, tipi di dati, ecc.

Esistono quattro tipi diversi di ISA:

    CISC - Complex Instruction Set Computing (insieme di istruzioni complesse)
    RISC - Reduced Instruction Set Computing (set di istruzioni ridotto)
    VLIW - Parola di istruzione molto lunga
    EPIC - Explicitly Parallel Instruction Computing (calcolo esplicitamente parallelo delle istruzioni)

RISC

RISC è l'acronimo di Reduced Instruction Set Computer (computer a set di istruzioni ridotte), un'architettura di microprocessori che mira a semplificare la complessità del set di istruzioni per la programmazione assembly a un ciclo di clock. Ciò comporta frequenze di clock più elevate per la CPU, ma consente un'esecuzione più rapida perché vengono utilizzati set di istruzioni più piccoli. Per set di istruzioni si intende l'insieme di istruzioni macchina che un determinato processore può eseguire. Oggi, ad esempio, possiamo trovare RISC nella maggior parte degli smartphone. Tuttavia, quasi tutte le CPU contengono una parte di RISC. Le architetture RISC hanno una lunghezza fissa di istruzioni definita come 32 e 64 bit.
CISC

A differenza del RISC, il Complex Instruction Set Computer (CISC) è un'architettura di processore con un set di istruzioni esteso e complesso. A causa dello sviluppo storico dei computer e della loro memoria, nei computer di seconda generazione le sequenze di istruzioni ricorrenti sono state combinate in istruzioni complesse. L'indirizzamento nelle architetture CISC non richiede 32 o 64 bit a differenza di RISC, ma può essere effettuato con una modalità a 8 bit.
Ciclo di istruzioni

Il set di istruzioni descrive l'insieme delle istruzioni macchina di un processore. La portata del set di istruzioni varia notevolmente a seconda del tipo di processore. Ogni CPU può avere cicli di istruzioni e set di istruzioni diversi, ma tutti hanno una struttura simile, che possiamo riassumere come segue:

Descrizione delle istruzioni

1. FETCH L'indirizzo dell'istruzione macchina successiva viene letto dal registro dell'indirizzo dell'istruzione (IAR). Viene quindi caricato dalla cache o dalla RAM nel registro delle istruzioni (IR).
2. DECODE Il decodificatore di istruzioni converte le istruzioni e avvia i circuiti necessari per eseguirle.
3. OPERANDE DI FETCH Se per l'esecuzione devono essere caricati altri dati, questi vengono caricati dalla cache o dalla RAM nei registri di lavoro.
4. ESECUZIONE L'istruzione viene eseguita. Può trattarsi, ad esempio, di operazioni nell'ALU, di un salto nel programma, della scrittura dei risultati nei registri di lavoro o del controllo di periferiche. A seconda del risultato di alcune istruzioni, viene impostato il registro di stato, che può essere valutato da istruzioni successive.
5. Se nella fase EXECUTE non è stata eseguita alcuna istruzione di salto, la IAR viene aumentata della lunghezza dell'istruzione in modo da puntare all'istruzione macchina successiva.