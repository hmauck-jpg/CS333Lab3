// Haleah Mauck
// 2/13/2026
// CS-314-006
// Lab3 desplodocus
// hmauck@pdx.edu
// this is the implementation file for the desplodocus program
 
//valgrind --leak-check=full --show-leak-kinds=all
//./desplodocus_mt -i hashes-nosalt-10.txt -p passwords-10.txt -t 1 -n -o v2.data

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/resource.h>
#include <crypt.h>
#include <string.h>
#include <fcntl.h>



#define OPTIONS "i:p:o:nt:vh"
#define NICE_INCREMENT 10


#ifdef NOISY_DEBUG 
# define NOISY_DEBUG_PRINT fprintf(stderr, "%s %s %d\n", __FILE__, __func__, __LINE__)
#else // NOISY_DEBUG
# define NOISY_DEBUG_PRINT
#endif // NOISY_DEBUG

static int v = 0;
static char * SALT = "./abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

//struct to hold hashes, plaintext passwords and mutex
typedef struct {
    char **hashes;
    int hashCount;

    char **passwords;
    int passwordCount;

    //TRY
    char ** results;

    int nextHash;
    pthread_mutex_t lock;
} shared_data_t;

//use calloc, to get array, each string is null terminated 

//struct for each thread
typedef struct {
    int threadId;
    int cracked;
    int failed;
    int total;
    shared_data_t *shared;
} thread_data_t;



// Desc: Reads all hashes from the hash file 
// Inputs: A pointer to a struct, which hold all hashes
// passwords, and cracked results
// and a char pointer to the name of the hash file
// Return: Int, 1 if successful 
int readHashes(shared_data_t  * data, char * DESfile);

// Desc: Reads all passwords from the password file 
// Inputs: A pointer to a struct, which hold all hashes
// passwords, and cracked results
// and a char pointer to the name of the password file
// Return: Int, 1 if successful 
int readPasswords(shared_data_t * data, char * passwordFile);


// Desc: Gives each thread a struct of data, times an infinite loop
// in which the mutex is unlocked and locked to access the next hash index
// and the thread iterates through all passwords, and all 4069 possible salts 
// to crack the hash correspoding to the index, while storing all cracked or failed
// hashes in the in parameter of shared data between all threads
// Inputs: void pointer to a struct of thread data for this thread
// Return: Void 
void * threadFunction(void * thread);


// Desc: Cleans up and deallocates all allocated memory in existance at time of termination
// Inputs: pthread_t pointer to all the thread ids, thread_data_t pointer to the thread data, char pointer to the 
// name of the output file, shared_data_t pointer to the struct of all hashes, passwords and results
// FILE pointer to the outfile descriptor 
// Return: Void
void cleanUp(pthread_t * tids, thread_data_t * threads, char * outFile, shared_data_t * data, FILE * fp);
 

int main(int argc, char * argv[]) {

     
    char * DESfile = NULL; //name of DES hash file
    char * passwordFile = NULL; //name of the plaintext password file
    char * outFile = NULL; //name of the output file, default to stdout
    FILE * fp = stdout; //out file pointer set to stdout
   
    int threadCount =  1; //number of threads to use
    shared_data_t data = {0}; //struct holding hashes, passwords and mutex
    pthread_t * tids = NULL; //array of thread ids
    thread_data_t * threads = NULL; //array of structs containing threads data
     

    int totalCracked = 0; //total cracked hashes
    int totalFailed = 0; //total failed hashes
    int totalProcessed = 0; //total hashes proccessed by all threads

    struct timeval start, end; 
    double elapsed = 0.0; //seconds from thread creation to thread joining


    NOISY_DEBUG_PRINT;

    {

        int opt = -1;
        NOISY_DEBUG_PRINT;
        while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
            switch (opt) {
                case 'i':
                     DESfile = optarg;
                     break;
                case 'p':
                    passwordFile = optarg;
                    break;
                case 'o':
                    outFile = optarg;
                    break;
                case 'n':
                    if(nice(NICE_INCREMENT) == -1) {
                        fprintf(stderr, "Failed to increment nice");
                        exit(EXIT_FAILURE);
                    }
                    break;
                case 't':
                    //get the number of threads to use 
                    threadCount = atoi(optarg);
                    break;
                case 'v':
                    v = 1;
                    break;
                case 'h':
                    printf("help text\n");
                    printf("        desplodocus_mt ...\n");
                    printf("        Options: i:o:p:t:nvh\n");
                    printf("                -i file         hash file name (required)\n");
                    printf("                -p file         plain word file name (required)\n");
                    printf("                -o file         output file name (default stdout)\n");
                    printf("                -t #            number of threads to create (default 1)\n");
                    printf("                -n              be nice\n");
                    printf("                -v              enable verbose mode\n");
                    printf("                -h              helpful text\n");
                    cleanUp(tids, threads, outFile, &data, fp);
                    exit(EXIT_SUCCESS);
                    break;
                default:
                    cleanUp(tids, threads, outFile, &data, fp);
                    exit(EXIT_FAILURE);
                    break;
            }

        }

    }

    if (v) {
        printf("Password file argument: %s\n", passwordFile);
    }
     
 

    NOISY_DEBUG_PRINT;
    if (outFile) {
        fp = fopen(outFile, "w");
        NOISY_DEBUG_PRINT;
        if (!fp) {
            NOISY_DEBUG_PRINT;
            fprintf(stderr, "Output file %s refused to open", outFile); 
            cleanUp(tids, threads, outFile, &data, fp);
            exit(EXIT_FAILURE); 
        }   
    }


    NOISY_DEBUG_PRINT;
    if (!DESfile || !passwordFile) {
        fprintf(stderr, "Hash and Password files not specified");
        cleanUp(tids, threads, outFile, &data, fp);
        exit(EXIT_FAILURE);
    }

    
    //allocate memory for tids and threads
    tids = malloc(threadCount * sizeof(pthread_t));
    threads = malloc(threadCount * sizeof(thread_data_t));


    NOISY_DEBUG_PRINT;
    //initalize mutex
    data.nextHash = 0;

    if (pthread_mutex_init(&data.lock, NULL) != 0) {
        fprintf(stderr, "Failed to initalize mutex");
        cleanUp(tids, threads, outFile, &data, fp);
        exit(EXIT_FAILURE);
    }

    data.hashCount = 0;
    data.passwordCount = 0;

    //getting hashes and passwords line by line
    //want 2 arrays of strings inside struct
    //read file first count lines
    //allocate exact memory
    //read file, storing strings 
    //use fopen and getline
    NOISY_DEBUG_PRINT;
    if (!readHashes(&data, DESfile)) {
        fprintf(stderr, "Empty hash file");
        cleanUp(tids, threads, outFile, &data, fp);
        exit(EXIT_FAILURE);
    }
    if (v) {
        printf("Loaded %d hashes\n", data.hashCount);
    }
     
     
    NOISY_DEBUG_PRINT;
    if (!readPasswords(&data, passwordFile)) {
        fprintf(stderr, "Empty password file");
        cleanUp(tids, threads, outFile, &data, fp);
        exit(EXIT_FAILURE);
    }
    
    if (v) {
        printf("Loaded %d passwords\n", data.passwordCount);
    }

    //TRY
    //allocate memory for results 
    data.results = calloc(data.hashCount, sizeof(char *)); 
     
    //start the timer
    gettimeofday(&start, NULL);

    NOISY_DEBUG_PRINT;
    //create threads
    //initalize an array of thread ids, and an array of thread data structs
    //make as many threads, as specified on command line 
    for (int i = 0; i < threadCount; ++i) {

        threads[i].threadId = i;
        threads[i].cracked = 0;
        threads[i].failed = 0;
        threads[i].total = 0;
        threads[i].shared = &data;

        pthread_create(&tids[i], NULL, threadFunction, &threads[i]);
    }

    NOISY_DEBUG_PRINT;
    //join threads
    for (int i = 0; i < threadCount; ++i) {
        pthread_join(tids[i], NULL);
    }

    //TRY
    //print results
    for (int i = 0; i < data.hashCount; ++i) {
        if (data.results[i]) {
            fprintf(fp, "%s", data.results[i]);
        } 
    }


    //stop the timer
    gettimeofday(&end, NULL);

  
     NOISY_DEBUG_PRINT;
    //sum the total, cracked, and failed passwords from each thread
    for (int i = 0; i < threadCount; ++i) {
        totalCracked += threads[i].cracked;
        totalFailed += threads[i].failed;
        totalProcessed += threads[i].total;
    }

    //calculate the elapsed time in seconds 
    elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;

    NOISY_DEBUG_PRINT;
    //print total summary
    fprintf(stderr, "total : %d    %.2f sec cracked:     %d failed: %d total: %d\n", threadCount, elapsed, totalCracked, totalFailed, totalProcessed);


    //clean, deallocate memory 
    pthread_mutex_destroy(&data.lock);

    cleanUp(tids, threads, outFile, &data, fp);
 
    return EXIT_SUCCESS;
}

 

// Desc: Gives each thread a struct of data, times an infinite loop
// in which the mutex is unlocked and locked to access the next hash index
// and the thread iterates through all passwords, and all 4069 possible salts 
// to crack the hash correspoding to the index, while storing all cracked or failed
// hashes in the in parameter of shared data between all threads
// Inputs: void pointer to a struct of thread data for this thread
// Return: Void 
void cleanUp(pthread_t * tids, thread_data_t * threads, char * outFile, shared_data_t * data, FILE * fp) {

    if( data && data->hashes) {
         for (int i = 0; i < data->hashCount; i++) {
            free(data->hashes[i]);
        }
        free(data->hashes);
    }
    
    if(data && data->passwords) {
         for (int i = 0; i < data->passwordCount; i++) {
            free(data->passwords[i]);
        }
        free(data->passwords);
    }

    //TRY add
    if(data && data->results) {
         for (int i = 0; i < data->hashCount; i++) {
            free(data->results[i]);
        }
        free(data->results);
    }


    free(tids);
    free(threads);
    
    if (outFile) {
        fclose(fp);
    }
    
    return;

}

    


// Desc: Gives each thread a struct of data, times an infinite loop
// in which the mutex is unlocked and locked to access the next hash index
// and the thread iterates through all passwords, and all 4069 possible salts 
// to crack the hash correspoding to the index, while storing all cracked or failed
// hashes in the in parameter of shared data between all threads
// Inputs: void pointer to a struct of thread data for this thread
// Return: Void 
void *threadFunction(void * thread) {
    
    thread_data_t *tdata = (thread_data_t *) thread;
    shared_data_t *shared = tdata->shared;
    int index = 0;
    int cracked = 0;
    char * result = NULL;
    struct crypt_data cdata;
    struct timeval start, end;
    double elapsed = 0.0;
    char buffer[256];
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
                    /* if (strcmp(shared->hashes[index],"k.9r3wNfev2") == 0 && (strcmp(salt, "Sb") == 0) && (strcmp(shared->passwords[p], "Tx42sfqp") == 0)) {
                        printf("Trying password=%s  salt=%s  result=%s  target=%s\n", shared->passwords[p], salt, result, shared->hashes[index]);
                    }*/

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
                        //BUT try not if only storing result
                        //pthread_mutex_lock(&shared->lock);
                        //printf("cracked: %s : %s\n", shared->hashes[index], tdata->shared->passwords[p]);
                        //TRY instead
                        snprintf(buffer, sizeof(buffer), "cracked: %s : %s\n", shared->hashes[index], tdata->shared->passwords[p]);
                        shared->results[index] = strdup(buffer);

                        if (v) {
                            printf("result: %s salt: %s\n", result, salt);
                        }

                        //pthread_mutex_unlock(&shared->lock);
                       
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
            //BUT try not if only storing result 
            //pthread_mutex_lock(&shared->lock);
            //printf("*** failed: %s\n", shared->hashes[index]);
            //TRY instead
            snprintf(buffer, sizeof(buffer),"*** failed: %s\n", shared->hashes[index]);
            shared->results[index] = strdup(buffer);

            //pthread_mutex_unlock(&shared->lock);

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



// Desc: Reads all hashes from the hash file 
// Inputs: A pointer to a struct, which hold all hashes
// passwords, and cracked results
// and a char pointer to the name of the hash file
// Return: Int, 1 if successful 
int readHashes(shared_data_t * data, char * DESfile) {

    FILE * DESfp; // hash file pointer
    char * line = NULL;
    size_t length = 0;
    ssize_t read;

    if(!(DESfp = fopen(DESfile, "r"))) {
            fprintf(stderr, "Failed to open hash file for counting lines");
            exit(EXIT_FAILURE);
        }
        //count hashes 
        while ((read = getline(&line, &length, DESfp)) != -1) {
            ++data->hashCount;
        }

        free(line);
        line = NULL;
        length = 0; 
        fclose(DESfp);

        //allocate data for hashes
        data->hashes = calloc(data->hashCount, sizeof(char*));

         if(!(DESfp = fopen(DESfile, "r"))) {
            fprintf(stderr, "Failed to open hash file for reading data");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; ((read = getline(&line, &length, DESfp)) != -1) && i < data->hashCount; ++i) {
            
            //remove newline
            if (line[read - 1] == '\n') {
                line[read - 1] = '\0';
            }

            //add hash to struch
            data->hashes[i] = strdup(line);
        }

        //why does line need freed when it was never malloced?
        //can the same variable line be used and freed both times line this?
        free(line);
        line = NULL;
        length = 0;
        fclose(DESfp);

        return (data->hashCount > 0) ? 1 : 0;

}

// Desc: Reads all passwords from the password file 
// Inputs: A pointer to a struct, which hold all hashes
// passwords, and cracked results
// and a char pointer to the name of the password file
// Return: Int, 1 if successful 
int readPasswords(shared_data_t * data, char * passwordFile) {

    FILE * passFp; // password file pointer
    char * line = NULL;  
    size_t length = 0; 
    ssize_t read;

    //open password file for read
    if(!(passFp = fopen(passwordFile, "r"))) {
        fprintf(stderr, "Failed to open password file");
        exit(EXIT_FAILURE);
    }
    //count passwords
    while ((read = getline(&line, &length, passFp)) != -1) {
        ++data->passwordCount;
    }

    free(line);
    line = NULL;
    length = 0;
    fclose(passFp);

    data->passwords = calloc(data->passwordCount, sizeof(char*));

    if(!(passFp = fopen(passwordFile, "r"))) {
        fprintf(stderr, "Failed to open password file for reading data");
        exit(EXIT_FAILURE);
    }
 
    for (int i = 0; ((read = getline(&line, &length, passFp)) != -1) && i < data->passwordCount; ++i) {
            
        //remove newline
        if (line[read - 1] == '\n') {
            line[read - 1] = '\0';
        }

        //add hash to struct
        data->passwords[i] = strdup(line);
    }

    free(line);
    fclose(passFp);

    return (data->passwordCount > 0) ? 1 : 0;
}

 
 