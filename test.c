#define _XOPEN_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <crypt.h>
#include <string.h>

// running ./desplodocus_mt -i hashes-nosalt-10.txt -p passwords-10.txt -t 1 -n > cracked-nosalt-h10-t1-nosort-s.out 2> cracked-nosalt-h10-t1-nosort-s.err

//gcc -Wall -g  test.c -o test -lcrypt

//from test script
//cracked: k.9r3wNfev2 : Tx42sfqp

static char * SALT = "./abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

int main() {
    struct crypt_data data;
    char * result = NULL;
    int cracked = 0;
    char * bob = "9r3wNfev2";
    char * sally = NULL;

    memset(&data, 0, sizeof(data));

    printf("hash: k.9r3wNfev2\n");
     
     for (int i = 0; i < 64 && !cracked; ++i) {
                
        for(int j = 0; j < 64; ++j) {
            //generate next possible salt 
            char salt[3];
            salt[0] = SALT[i];
            salt[1] = SALT[j];
            salt[2] = '\0';

            result = crypt("Tx42sfqp", salt);

            if (strcmp(salt, "k.") == 0) {
                printf("salt: %s result: %s\n", salt, result);
            }

            sally = memmove(result, result + 2, strlen(result + 2) + 1);
            //printf("%s\n", sally);
            if (strcmp(bob, sally) == 0) {
                printf("salt: %s result: %s\n", salt, result);
            }
             


            if (strcmp(result,"k.9r3wNfev2") == 0) {
                printf("FOUND\n");
                printf("%s\n", salt);
                printf("%s\n", result);
                cracked = 1;
            }
             

        }

    }

     
   
     
   /* printf("%s\n", crypt("HER9027", "k."));
    printf("%s\n", crypt("nar34lics", "k."));
    printf("%s\n", crypt("packmoose", "k."));
    printf("%s\n", crypt("LzAW476a", "k."));
    printf("%s\n", crypt("7661FTG", "k.")); 
    printf("%s\n", crypt("Tx42sfqp", "k.")); 
    printf("I should be: k.9r3wNfev2\n");
    printf("%s\n", crypt("Falkirk1", "k."));
    printf("%s\n", crypt("zyfjltujdf", "k."));
    printf("%s\n", crypt("huhzcl", "k."));
    printf("%s\n", crypt("piligrim2011", "k."));
    printf("%s\n", crypt("chickenelvyra", "k."));
    printf("%s\n", crypt("spqr", "k."));
    printf("%s\n", crypt("blp953", "k."));
    printf("%s\n", crypt("fphillip", "k."));
    printf("%s\n", crypt("kareenj07", "k."));
    printf("%s\n", crypt("motia", "k."));
    printf("%s\n", crypt("wishart8", "k."));
    printf("%s\n", crypt("SAGIAM", "k."));
    printf("%s\n", crypt("spYfI3XYDPPH2", "k.")); */
     

    return 0;
}




 /*
           //loop through all possible salts
            //consider replaced 64 with defined macro
            //do this instead of taking first two chars as the salt
            for (int i = 0; i < 64 && !cracked; ++i) {
                
                for(int j = 0; j < 64; ++j) {
                    //generate next possible salt 
                    char salt[3];
                    salt[0] = SALT[i];
                    salt[1] = SALT[j];
                    salt[2] = '\0';
        
*/

//gcc -D_XOPEN_SOURCE desplodocus_mt.c -o desplodocus_mt -pthread -lcrypt
//gcc -Wall -g -D_GNU_SOURCE test.c -o test -lcrypt
//gcc -Wall -g -D_XOPEN_SOURCE=600 test.c -o test -lcrypt
 

/*
 cat hashes-nosalt-10.txt

lyKKhmawu..
47bgoaMeUIE
VApfn8gHvXo
k.9r3wNfev2
it0W5QVJSIo
JQRJsNGCALs
ZIdWMELChIc
d90dBVJeHYA
cvdeMKMexuU
qoRCxgk5DeQ
*/

/*
cat passwords-10.txt

HER9027
nar34lics
packmoose
LzAW476a
7661FTG
Tx42sfqp
Falkirk1
zyfjltujdf
1997vik
huhzcl
piligrim2011
chickenelvyra
spqr
blp953
fphillip
kareenj07
motia
wishart8
SAGIAM
spYfI3XYDPPH2
*/
