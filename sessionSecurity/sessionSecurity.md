# Tipologie di attacchi alla sessione

- Session hijacking: Negli attacchi di session hijacking, l'aggressore sfrutta gli identificatori di sessione non sicuri, trova un modo per ottenerli e li usa per autenticarsi al server e impersonare la vittima.

- Session fixation: La session fixation si verifica quando un aggressore riesce a fissare un identificatore di sessione (valido). Come si può immaginare, l'aggressore dovrà quindi ingannare la vittima per farla accedere all'applicazione utilizzando il suddetto identificatore di sessione. Se la vittima lo fa, l'aggressore può procedere a un attacco di Session Hijacking (poiché l'identificatore di sessione è già noto).

- XSS: con particolare attenzione alle sessioni degli utenti

- CSRF: Il Cross-Site Request Forgery (CSRF o XSRF) è un attacco che costringe un utente finale a eseguire azioni involontarie su un'applicazione Web in cui è attualmente autenticato. Questo attacco viene solitamente sferrato con l'aiuto di pagine Web create dall'aggressore che la vittima deve visitare o con cui deve interagire. Queste pagine web contengono richieste dannose che ereditano essenzialmente l'identità e i privilegi della vittima per eseguire una funzione indesiderata per conto di quest'ultima.

- Open redirect: Una vulnerabilità Open Redirect si verifica quando un aggressore può reindirizzare una vittima a un sito controllato dall'aggressore abusando della funzionalità di reindirizzamento di un'applicazione legittima. In questi casi, tutto ciò che l'aggressore deve fare è specificare un sito web sotto il suo controllo in un URL di reindirizzamento di un sito web legittimo e passare questo URL alla vittima. Come si può immaginare, ciò è possibile quando la funzionalità di reindirizzamento dell'applicazione legittima non esegue alcun tipo di convalida dei siti web a cui il reindirizzamento punta.

# Session hijacking

L'identificativo di sessione si puo' ottenere in diversi modi:

- Passive Traffic Sniffing
- Cross-Site Scripting (XSS)
- Browser history or log-diving
- Read access to a database containing session information



# Session fixation

Gli attacchi di fissazione della sessione si svolgono solitamente in tre fasi:

1. l'attaccante riesce a ottenere un identificatore di sessione valido.
L'autenticazione a un'applicazione non è sempre un requisito per ottenere un identificatore di sessione valido e un gran numero di applicazioni assegna identificatori di sessione validi a chiunque vi navighi. Ciò significa anche che a un utente malintenzionato può essere assegnato un identificatore di sessione valido senza doversi autenticare.
Nota: un aggressore può ottenere un identificatore di sessione valido anche creando un account sull'applicazione bersaglio (se è possibile).

2. l'attaccante riesce a fissare un identificatore di sessione valido
Quanto sopra è un comportamento atteso, ma può trasformarsi in una vulnerabilità di fissazione della sessione se (entrambi i punti): 
  - L'identificatore di sessione assegnato prima dell'accesso rimane lo stesso dopo l'accesso.
  - Gli identificatori di sessione (come i cookie) vengono accettati da stringhe di query URL o dati post e propagati all'applicazione.
Se, ad esempio, un parametro relativo alla sessione è incluso nell'URL (e non nell'intestazione del cookie) e qualsiasi valore specificato diventa un identificatore di sessione, l'attaccante può fissare una sessione.

3. l'attaccante induce la vittima a stabilire una sessione utilizzando il suddetto identificatore di sessione

Tutto ciò che l'attaccante deve fare è creare un URL e attirare la vittima a visitarlo. Se la vittima lo fa, l'applicazione Web le assegnerà questo identificatore di sessione.

L'aggressore può quindi procedere a un attacco session hijacking, poiché l'identificatore di sessione è già noto.


# XSS

Affinché un attacco di Cross-Site Scripting (XSS) provochi un leak di cookie di sessione, devono essere soddisfatti i seguenti requisiti:
- i cookie di sessione devono essere presenti in tutte le richieste HTTP
- I cookie di sessione devono essere accessibili dal codice JavaScript (l'attributo HTTPOnly deve essere assente)

# CSRF


Un attacco CSRF riuscito può compromettere i dati e le operazioni dell'utente finale quando è rivolto a un utente normale. Se l'utente finale preso di mira è un utente amministrativo, un attacco CSRF può compromettere l'intera applicazione Web.

Durante gli attacchi CSRF, l'attaccante non ha bisogno di leggere la risposta del server alla richiesta cross-site dannosa. Ciò significa che il criterio Same-Origin non può essere considerato un meccanismo di sicurezza contro gli attacchi CSRF.

Ricordiamo che..: Secondo Mozilla, same-origin policy è un meccanismo di sicurezza critico che limita il modo in cui un documento o uno script caricato da un'origine può interagire con una risorsa di un'altra origine. La same-origin policy non consente a un utente malintenzionato di leggere la risposta del server a una richiesta cross-site dannosa.

Un'applicazione Web è vulnerabile agli attacchi CSRF quando:

- Tutti i parametri necessari per la richiesta mirata possono essere determinati o indovinati dall'aggressore.
- La gestione della sessione dell'applicazione si basa esclusivamente sui cookie HTTP, che vengono automaticamente inclusi nelle richieste del browser.

Per sfruttare con successo una vulnerabilità CSRF, occorre:

- Creare una pagina web dannosa che emetta una richiesta valida (cross-site) impersonando la vittima.
- La vittima sia collegata all'applicazione nel momento in cui viene emessa la richiesta cross-site dannosa.

Durante i test di penetrazione delle applicazioni Web o la caccia ai bug, noterete molte applicazioni prive di protezioni anti-CSRF o con protezioni anti-CSRF che possono essere facilmente aggirate.

A volte, anche se riusciamo a bypassare le protezioni CSRF, potremmo non essere in grado di creare richieste cross-site a causa di una sorta di restrizione relativa alla stessa origine/stesso sito. In questo caso, possiamo provare a concatenare le vulnerabilità per ottenere il risultato finale del CSRF.

Spesso le applicazioni Web non utilizzano algoritmi di generazione dei token molto sicuri o robusti. Un esempio è un'applicazione che genera token CSRF come segue (pseudocodice): md5(username).

Come possiamo capire se questo è il caso? Possiamo registrare un account, esaminare le richieste per identificare un token CSRF e poi verificare se l'hash MD5 del nome utente è uguale al valore del token CSRF.

# Open redirect
Una vulnerabilità Open Redirect si verifica quando un aggressore può reindirizzare una vittima a un sito controllato dall'aggressore abusando della funzionalità di reindirizzamento di un'applicazione legittima. In questi casi, tutto ciò che l'aggressore deve fare è specificare un sito web sotto il suo controllo in un URL di reindirizzamento di un sito web legittimo e passare questo URL alla vittima. Come si può immaginare, ciò è possibile quando la funzionalità di reindirizzamento dell'applicazione legittima non esegue alcun tipo di convalida dei siti web a cui punta il reindirizzamento. Dal punto di vista di un aggressore, una vulnerabilità di reindirizzamento aperto può rivelarsi estremamente utile durante la fase di accesso iniziale, poiché può condurre le vittime a pagine web controllate dall'aggressore attraverso una pagina di cui si fidano.

una cosa cosi puo' succere con un url del tipo `trusted.site/index.php?url=https://evil.com`

# Rimedi 

## Session hijacking

È piuttosto difficile contrastare il hijacking di sessione, poiché un identificatore di sessione valido garantisce l'accesso a un'applicazione per impostazione predefinita. Le soluzioni di monitoraggio delle sessioni utente e di rilevamento delle anomalie possono rilevare l'hijacking di sessione. È più sicuro contrastare il hijacking di sessione cercando di eliminare tutte le vulnerabilità descritte in questo modulo.

## Remediating Session Fixation

Ideally, session fixation can be remediated by generating a new session identifier upon an authenticated operation. Simply invalidating any pre-login session identifier and generating a new one post-login should be enough.

## Remediating XSS

Ideally, XSS can be remediated by following the below secure coding practices:

- Validation of user input
- HTML encoding to user-controlled output
- Do not embed user input into client-side scripts. Values deriving from user input should not be directly embedded as part of an HTML tag, script tag (JS/VBS), HTML event, or HTML property.
- Complimentary instructions for protecting the application against cross-site scripting can be found at the following URL: Cross Site Scripting Prevention Cheat Sheet
- A list of HTML encoded character representations can be found at the following URL: Special Characters in HTML

## Remediating CSFR

The preferred way to reduce the risk of a Cross-Site Request Forgery (CSRF) vulnerability is to modify session management mechanisms and implement additional, randomly generated, and non-predictable security tokens (a.k.a Synchronizer Token Pattern) or responses to each HTTP request related to sensitive operations.

In addition to the above, explicitly stating cookie usage with the SameSite attribute can also prove an effective anti-CSRF mechanism.

https://web.dev/samesite-cookies-explained/

## Remediating Open Redirect

The safe use of redirects and forwards can be done in several ways:

- Do not use user-supplied URLs (or partial URL elements) and have methods to strictly validate the URL.
- If user input cannot be avoided, ensure that the supplied value is valid, appropriate for the application, and is authorized for the user.
- It is recommended that any destination input be mapped to a value rather than the actual URL or portion of the URL and that server-side code translates this value to the target URL.
- Sanitize input by creating a list of trusted URLs (lists of hosts or a regex).
- Force all redirects to first go through a page notifying users that they are being redirected from your site and require them to click a link to confirm (a.k.a Safe Redirect).



http://minilab.htb.net/submit-solution?url=http://minilab.htb.net/profile?email=julie.rogers@example.com


http://10.10.15.253/