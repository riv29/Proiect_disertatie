gcc -c ../RSA.c \
	../../SHA/SHA.c \
        ../../SHA/SHA3.c \
        ../../Key_Gen/GenPrimes.c \
        ../../ASN/ASN.c \
        ../../Base64/Base64.c\
        test.c &&\
	gcc *.o -o app -lgmp
