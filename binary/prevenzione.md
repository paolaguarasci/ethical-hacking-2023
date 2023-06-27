# Tecniche e meccanismi di prevenzione

La migliore protezione contro i buffer overflow è una programmazione attenta alla sicurezza. Gli sviluppatori di software dovrebbero informarsi sulle insidie del caso e impegnarsi per una programmazione deliberatamente sicura. Inoltre, esistono meccanismi di sicurezza che supportano gli sviluppatori e impediscono agli utenti di sfruttare tali vulnerabilità.

Tra questi vi sono i meccanismi di sicurezza:

- Canaries
- randomizzazione del layout dello spazio degli indirizzi (ASLR)
- Prevenzione dell'esecuzione dei dati (DEP)


## Canaries
I Canaries sono valori noti scritti nello stack tra il buffer e i dati di controllo per rilevare gli overflow del buffer. Il principio è che in caso di overflow del buffer, il canary viene sovrascritto per primo e che il sistema operativo controlla in fase di esecuzione che il canary sia presente e inalterato.

## Randomizzazione del layout dello spazio degli indirizzi (ASLR)
L'Address Space Layout Randomization (ASLR) è un meccanismo di sicurezza contro i buffer overflow. Rende più difficili alcuni tipi di attacchi rendendo difficile l'individuazione degli indirizzi di destinazione nella memoria. Il sistema operativo utilizza ASLR per nascondere gli indirizzi di memoria rilevanti. È quindi necessario indovinare gli indirizzi, dove un indirizzo sbagliato molto probabilmente causa un crash del programma e, di conseguenza, esiste un solo tentativo.

## Prevenzione dell'esecuzione dei dati (DEP)
DEP è una funzione di sicurezza disponibile in Windows XP, e successivamente con il Service Pack 2 (SP2) e oltre, i programmi vengono monitorati durante l'esecuzione per garantire che accedano alle aree di memoria in modo pulito. DEP termina il programma se un programma tenta di chiamare o accedere al codice del programma in modo non autorizzato.