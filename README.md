# Resurse folosite pana in momentul de fata:

Criptare simterica:  
	&emsp;1. [RC6](BlockChipers/RC6): [https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf](https://people.csail.mit.edu/rivest/pubs/RRSY98.pdf)  
	&emsp;2. [AES](BlockChipers/AES):  
		&emsp;&emsp;- [Cursul 4](resurse) din fisierul de resurse contine explicatii pentru AES.  
		&emsp;&emsp;- Prezentare grafica: [https://www.youtube.com/watch?v=gP4PqVGudtg&t=156s](https://www.youtube.com/watch?v=gP4PqVGudtg&t=156s)  
		&emsp;&emsp;- Specificatie NIST: [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) (Capitolul 5, Apendix pentru test)  
	&emsp;3. [DES](BlockChipers/DES):  
		&emsp;&emsp;- [Cursul 3](resurse) din fisierul de resurse contine explicatii pentru DES.  
		&emsp;&emsp;- Specificatii NIST: [https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf](https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf)  
		&emsp;&emsp;- Triple DES este o extensie pentru DES  
	&emsp;4. De asemenea am incluse si [modurile de operare](BlockChipers/Modes) pentru folosirea cifrurilor pe bloc.  

Functii de hashing:  
	&emsp;1. [SHA1 + SHA2](Hash/SHA/SHA.c): [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)  
	&emsp;2. [SHA3](Hash/SHA/SHA3.c): [https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)  
	&emsp;3. Am avut nevoie si de urmatorul proiect pentru implementarea colectiei de algoritmi SHA3 deoarece am avut nevoie de referinte pentru a putea interpreta specificatia de la NIST:  
	    &emsp;&emsp;- [https://github.com/brainhub/SHA3IUF](https://github.com/brainhub/SHA3IUF)  

Criptare asimetrica:  
	&emsp;1. Specificatie NIST: [https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.186-4.pdf](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.186-4.pdf)  
		&emsp;&emsp;- Apendix A.1.1.1, A.1.1.2 si A.1.1.3 contin algoritmii necesari pentru generarea numerelor prime (p si q) folosite in cadrul cifrurilor asimetrice.  
		&emsp;&emsp;- Apendix C descrie o serie de algoritmi folositi pentru verificarea primalitatii numerelor generate.  
		    &emsp;&emsp;&emsp;- Eu am implementat algoritmul Miller-Rabin pentru testul de primalitate.  
	&emsp;2. Proiectul openssl: [https://github.com/openssl/openssl](https://github.com/openssl/openssl)  
		&emsp;&emsp;- M-am folosit si de codul sursa de la proiectul openssl ca referinta, contine pasii mentionati in FIPS 186-4.  
	&emsp;* Deocamdata am implementat [algoritmii](AsymetricCiphers/Key_Gen) pentru generarea numerelor prime.  
	&emsp;* Am implementat tot ce este necesar pentru folosirea cifrului [RSA](AsymetricCiphers/RSA). (Generare chei, semnare si verificare).  
	&emsp;* Algoritmul este descris si in [cursul 7](resurse) din fisierul de resurse.  
De asemenea, pentru stocarea perechilor de chei pentru cifrurile asimetrice am adaugat suport si pentru [ASN1](ASN), deocamdata pot stoca doar chei RSA.  
Am testat functionalitate prin generarea unei perechi de chei pe care am folosit-o pentru a realiza o conexiune ssh.  
Am implementat si encodarea in [baza 64](Encoding/Base64).  
# Va trebui implementat:  
Criptare simetrica:  
	&emsp;1. ARIA: [https://www.rfc-editor.org/rfc/rfc5794](https://www.rfc-editor.org/rfc/rfc5794)  
	&emsp;2. Blowfish  
	&emsp;3. Twofish  
	&emsp;- Ceilalti algoritmi folositi pentru criptarea simetrica nu au fost dificil de implementat.  
Criptare asimetrica:  
	&emsp;1. DSA:  
		&emsp;&emsp;- Partea de generare de chei este acoperita.  
		&emsp;&emsp;- Sunt explicati pasii in [cursul 9](resurse) din fisierul de resurse.  
		&emsp;&emsp;- De asemenea exista resurse in specificatiile din FIPS 186-4 si codul prezent in proiectul openssl.  
			&emsp;&emsp;&emsp;- Din cate am observat nu implica o dificultate foarte mare.  
	&emsp;2. DH si ECDH:	Deocamdata nu am cautat resurse, dar ma astept sa fie mai usor decat ce implica RSA sau DSA  
	&emsp;3. Includerea de chei eliptice: Sunt disponibile resurse in FIPS 186-4 Capitolul 6 si Apendix D, dar inca nu le-am studiat.  
PRNG (Pseudo Random Number Generator):  
	&emsp;Va fi necesar sa decid asupra unei metode de generare de numere pseudo-aleatoare, incerc sa ma orientez spre a folosi algoritmul Mersenne Twister.  
Pentru FPGA:  
	&emsp;Asi dori sa implementez un TRNG pe un FPGA pe care sa-l folosesc in paralel cu un PRNG.  
		&emsp;Ideea principala este de a genera un "seed" pentru PRNG, prin intermediul TRNG-ului.  
	&emsp;Am gasit urmatorul articol: [https://people.csail.mit.edu/devadas/pubs/ches-fpga-random.pdf](https://people.csail.mit.edu/devadas/pubs/ches-fpga-random.pdf)  
		&emsp;&emsp;Din cate inteleg, se doreste fortarea starii de metastabilitate, iar in felul asta se pot "cultiva" biti astfel incat sa obtii date aleatorii.  
		&emsp;&emsp;NIST ofera si un set de teste pentru verificare gradului de aleatorism, deocamdata nu am parcurs documentul, stiu doar ca poate fi de folos:  
			&emsp;&emsp;&emsp;[https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-22r1a.pdf)  
	&emsp;De asemenea exista si un proiect in acest sens dar care se foloseste de o alta metoda:  
		&emsp;&emsp;[https://github.com/stnolting/neoTRNG](https://github.com/stnolting/neoTRNG)  
