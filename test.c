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


//og threadFunction without ordering edits

/*



// Desc:
// Inputs:
// Return:
void *threadFunction(void * thread) {
    
    thread_data_t *tdata = (thread_data_t *) thread;
    shared_data_t *shared = tdata->shared;
    int index = 0;
    int cracked = 0;
    char * result = NULL;
    struct crypt_data cdata;
    struct timeval start, end;
    double elapsed = 0.0;
    //cdata.initialized = 0;
    //TRY
    memset(&cdata, 0, sizeof(struct crypt_data));
    //char salt[3];

    
    gettimeofday(&start, NULL);
 
     
    // start infnite loop 
    while (1) {

        //protect shared counter, cannot access shared resource unless unlocked
        pthread_mutex_lock(&shared->lock);

        index = shared->nextHash;
        ++shared->nextHash;

        //iterate to next hash within mutex
        pthread_mutex_unlock(&shared->lock);

        if (index >= shared->hashCount) {
            break;
        }


        //TRY
        //put memset inside the loop
        //memset(&cdata, 0, sizeof(struct crypt_data));

        cracked = 0;
 

        //run cracking loop for all passwords, while thread is not cracked
        for (int p = 0; p < shared->passwordCount && !cracked; ++p) {
            //char *password = shared->passwords[p];

            //loop through all possible salts
            //consider replaced 64 with defined macro
            for (int i = 0; i < 64 && !cracked; ++i) {
                for(int j = 0; j < 64; ++j) {
                    //generate next possible salt 
                    char salt[3];
                    salt[0] = SALT[i];
                    salt[1] = SALT[j];
                    salt[2] = '\0';

                    //result = crypt_rn(shared->passwords[p], salt, &cdata, sizeof(cdata));
                    result = crypt_r(shared->passwords[p], salt, &cdata);
                    //TRY using full hash in salt paratmeter, instead of 2 char salt 
                    //this generates the exact same set of hashes in crypt_r apparently 
                    //result = crypt_r(shared->passwords[p], shared->hashes[index], &cdata);
                    //TRY crypt instead of crypt_r
                    //result = crypt(shared->passwords[p], salt);

                    //DEBUG
                    //if (strcmp(shared->hashes[index],"k.9r3wNfev2") == 0 && (strcmp(salt, "Sb") == 0) && (strcmp(shared->passwords[p], "Tx42sfqp") == 0)) {
                        //printf("Trying password=%s  salt=%s  result=%s  target=%s\n", shared->passwords[p], salt, result, shared->hashes[index]);
                    //}

                    if (v) {
                        printf("Trying password=%s  salt=%s  result=%s  target=%s\n", shared->passwords[p], salt, result, shared->hashes[index]);
                    }
                     

                    //check if this password + salt cracked the hash
                    //result + 2 removes the salt from the resulting hash
                    //in no salt files, the hash is the result of salt, but the salt is removed after hashing
                    // mkpasswd -m des Tx42sfqp Sb  becomes Sbk.9r3wNfev2
                    //cracked: k.9r3wNfev2 : Tx42sfqp
                    if (strcmp(result + 2, shared->hashes[index]) == 0) {

                        //use mutex when printing result 
                        pthread_mutex_lock(&shared->lock);
                        printf("cracked: %s : %s\n", shared->hashes[index], tdata->shared->passwords[p]);

                        if (v) {
                            printf("result: %s salt: %s\n", result, salt);
                        }

                        pthread_mutex_unlock(&shared->lock);
                       
                        //interate this thread's number of cracked passwords
                        //good boy. 
                        ++tdata->cracked;
                        cracked = 1;
                        break;
                    } 
                }
                 
            }
            //end salt generation outer while loop
             
        }
        //end cracking loop for all passwords

        //check if the thread failed to crack the hash
        if (!cracked) {
            //use mutex when printing result 
            pthread_mutex_lock(&shared->lock);
            printf("*** failed: %s\n", shared->hashes[index]);
            pthread_mutex_unlock(&shared->lock);

            //iterate this threads number of failures
            //L for thread
            ++tdata->failed;
        }

        ++tdata->total;
            
        
    }
    //end of infinite loop

        
    // compute time difference
    gettimeofday(&end, NULL);
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

    //print this thread's summary
    //use the mutex to prevent interleaving
    pthread_mutex_lock(&shared->lock);
    fprintf(stderr, "thread: %2d %8.2f sec cracked: %5d failed: %5d total: %5d\n", tdata->threadId, elapsed, tdata->cracked, tdata->failed, tdata->total);
    pthread_mutex_unlock(&shared->lock);

    pthread_exit(NULL);


} 
*/
 