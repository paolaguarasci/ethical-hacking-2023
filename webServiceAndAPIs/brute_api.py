import requests, sys

def brute():
    try:
        value = range(10000)
        for val in value:
            url = sys.argv[1]
            
            # modificare con un parametro valido trovato enumerando i parametri
            # ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://<TARGET IP>:<TARGET PORT>/?FUZZ=test_value' -fs 19 
            r = requests.get(url + '/?id='+str(val))

            if "position" in r.text:
                print("Number found!", val)
                print(r.text)
    except IndexError:
        print("Enter a URL E.g.: http://<TARGET IP>:3003/")

brute()
