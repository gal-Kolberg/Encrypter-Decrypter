# Encrypter-Decrypter
Producer - Consumer problem implemented as Encrypter and Decrypter

# Do the following actions:
	1) unzip "Exersice2" to an empty directory
	2) run through the bash terminal: make
  	3) run through the bash terminal: sudo ./ex2 -n <Number_Of_Decrypters> -l <Password_Length> -t <Seconds_To_Wait_For_Encrypter>
		i. command for example: sudo ./ex2 -n 10 -l 16
    
# Notes
	1) the order of the keys can be different
	2) the key '-t' is optional
	3) the keys can be short or long:
			i.	for '-n' you can write '--num-of-decrypters'
			ii.	for '-l' you can write '--password-length'
			iii.	for '-t' you can write '--timeout'
