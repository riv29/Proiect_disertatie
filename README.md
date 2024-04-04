# Resurse folosite pana in momentul de fata:

## Criptare simterica:
	1. RC6: [https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf][1]
	2. AES:
		- Cursul 4 din fisierul de resurse contine explicatii pentru AES.
		- Prezentare grafica: [https://www.youtube.com/watch?v=gP4PqVGudtg&t=156s][2]
		- Specificatie NIST: [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf][3] (Capitolul 5, Apendix pentru test)
	3. DES:
		- Cursul 3 din fisierul de resurse contine explicatii pentru DES.
		- Specificatii NIST: [https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf][4]
		- Triple DES este o extensie pentru DES

	4. De asemenea am incluse si modurile de operare pentru folosirea cifrurilor pe bloc.

## Functii de hashing:
	1. SHA1 + SHA2: [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf][5]
	2. SHA3: [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf][6]
	
	3. Am avut nevoie si de urmatorul proiect pentru implementarea colectiei de algoritmi SHA3 deoarece am avut nevoie de referinte pentru a putea interpreta specificatia de la NIST:
	    - [https://github.com/brainhub/SHA3IUF][7]

## Criptare asimetrica:
	
	1. Specificatie NIST: [https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.186-4.pdf][8]

		- Apendix A.1.1.1, A.1.1.2 si A.1.1.3 contin algoritmii necesari pentru generarea numerelor prime (p si q) folosite in cadrul cifrurilor asimetrice.
		- Apendix C descrie o serie de algoritmi folositi pentru verificarea primalitatii numerelor generate.
		    - Eu am implementat algoritmul Miller-Rabin pentru testul de primalitate.

	2. Proiectul openssl: [https://github.com/openssl/openssl][9]
		- M-am folosit si de codul sursa de la proiectul openssl ca referinta, contine pasii mentionati in FIPS 186-4.

	Deocamdata am implementat algoritmii pentru generarea numerelor prime.
	Am implementat tot ce este necesar pentru folosirea cifrului RSA. (Generare chei, semnare si verificare).
	Algoritmul este descris si in cursul 7 din fisierul de resurse.

De asemenea, pentru stocarea perechilor de chei pentru cifrurile asimetrice am adaugat suport si pentru ASN1, deocamdata pot stoca doar chei RSA.
Am testat functionalitate prin generarea unei perechi de chei pe care am folosit-o pentru a realiza o conexiune ssh.
	
Am implementat si encodarea in baza 64.

# Va trebui implementat:
## Criptare simetrica:
	1. ARIA: [https://www.rfc-editor.org/rfc/rfc5794][10]
	2. Blowfish
	3. Twofish

	- Ceilalti algoritmi folositi pentru criptarea simetrica nu au fost dificil de implementat.		

## Criptare asimetrica:
	1. DSA:
		- Partea de generare de chei este acoperita.
		- Sunt explicati pasii in cursul 9 din fisierul de resurse.
		- De asemenea exista resurse in specificatiile din FIPS 186-4 si codul prezent in proiectul openssl.
			- Din cate am observat nu implica o dificultate foarte mare.

	2. DH si ECDH:	Deocamdata nu am cautat resurse, dar ma astept sa fie mai usor decat ce implica RSA sau DSA
		
	3. Includerea de chei eliptice: Sunt disponibile resurse in FIPS 186-4 Capitolul 6 si Apendix D, dar inca nu le-am studiat.

## PRNG (Pseudo Random Number Generator):
	Va fi necesar sa decid asupra unei metode de generare de numere pseudo-aleatoare, incerc sa ma orientez spre a folosi algoritmul Mersenne Twister.

# Pentru FPGA:
	
	Asi dori sa implementez un TRNG pe un FPGA pe care sa-l folosesc in paralel cu un PRNG.
		Ideea principala este de a genera un "seed" pentru PRNG, prin intermediul TRNG-ului.

	Am gasit urmatorul articol: [https://people.csail.mit.edu/devadas/pubs/ches-fpga-random.pdf][11]
		Din cate inteleg, se doreste fortarea starii de metastabilitate, iar in felul asta se pot "cultiva" biti astfel incat sa obtii date aleatorii.
		NIST ofera si un set de teste pentru verificare gradului de aleatorism, deocamdata nu am parcurs documentul, stiu doar ca poate fi de folos:
			[https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf][12]

	De asemenea exista si un proiect in acest sens dar care se foloseste de o alta metoda:
		[https://github.com/stnolting/neoTRNG][13]

[1]: https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf 
[2]: https://www.youtube.com/watch?v=gP4PqVGudtg&t=156s 
[3]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf 
[4]: https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf 
[5]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf 
[6]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf 
[7]: https://github.com/brainhub/SHA3IUF 
[8]: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.186-4.pdf 
[9]: https://github.com/openssl/openssl 
[10]: https://www.rfc-editor.org/rfc/rfc5794 
[11]: https://people.csail.mit.edu/devadas/pubs/ches-fpga-random.pdf 
[12]: https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf 
[13]: https://github.com/stnolting/neoTRNG
