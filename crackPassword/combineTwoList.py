import sys
import requests
import os.path

fname1 = sys.argv[1]
fname2 = sys.argv[2]
f = open("combined.txt", "w")

with open(fname1) as fh:
    # read file line by line
    for fline1 in fh:
        # skip line if it starts with a comment
        if fline1.startswith("#"):
            continue
        username = fline1
        with open(fname2) as fh:
            # read file line by line
            for fline2 in fh:
                # skip line if it starts with a comment
                if fline2.startswith("#"):
                    continue
                password = fline2
                combination = username.strip()+":"+password.strip()
                f.write(combination+"\n")
f.close()
