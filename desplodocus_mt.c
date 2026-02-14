// Haleah Mauck
// 2/13/2026
// CS-314-006
// Lab3 desplodocus
// hmauck@pdx.edu
// this is the implementation file for the desplodocus program
 

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/resource.h>
#include <crypt.h>
#include <string.h>


#define OPTIONS "i:p:o:nt:vh"
#define NICE_INCREMENT 10

static int v = 0;
static char * SALT = "./abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

//struct to hold hashes, plaintext passwords and mutex
typedef struct {
    char **hashes;
    int hashCount;

    char **passwords;
    int passwordCount;

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



// Desc:
// Inputs:
// Return:
int readHashes(shared_data_t  * data, char * DESfile);

// Desc:
// Inputs:
// Return:
int readPasswords(shared_data_t * data, char * passwordFile);

// Desc:
// Inputs:
// Return:
void * threadFunction(void * thread);
 

int main(int argc, char * argv[]) {

    char * DESfile = NULL; //name of DES hash file
    char * passwordFile = NULL; //name of the plaintext password file
    char * outFile; //name of the output file, default to stdout
    //should I declare an int here, a file descriptor for the output file
    //and set it to STDOUT_FILENO later, if there is no o on command line?
    int outfd = -1; //output file descriptor
    
    int threadCount =  1; //number of threads to use
    shared_data_t data; //struct holding hashes, passwords and mutex
    pthread_t * tids; //array of thread ids
    thread_data_t * threads; //array of structs containing threads data

    {

        int opt = -1;

        while ((opt = getopt(argc, argv, OPTIONS)) != -1) {
            switch (opt) {
                case 'i':
                     DESfile = strdup(optarg);
                     //how do I fail for no optarg?
                     break;
                case 'p':
                    passwordFile = strdup(optarg);
                    break;
                case 'o':
                    outFile = strdup(optarg);
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
                    //find the instructor specifed help message
                    exit(EXIT_SUCCESS);
                    break;
                default:
                    exit(EXIT_FAILURE);
                    break;
            }

        }

    }

    //is this the correct place to open the output file?
    if (outFile) {
        //what settings to I need to use?
        outfd = open(outFile, O_WRONLY);
    }
    else {
        outfd = STDOUT_FILENO;
    }

    if (!DESfile || !passwordFile) {
        fprintf(stderr, "Hash and Password files not specifed");
        exit(EXIT_FAILURE);
    }

    //is this the correct way to dynamically allocate memory? as I need to ensure no memory leaks
    //will these arrays work, as pointers to arrays?
    //allocate memory for tids and threads
    tids = malloc(threadCount * sizeof(pthread_t));
    threads = malloc(threadCount * sizeof(thread_data_t));



    //initalize mutex
    data.nextHash = 0;

    if (pthread_mutex_init(&data.lock, NULL) != 0) {
        fprintf(stderr, "Failed to initalize mutex");
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

    if (!readHashes(&data, DESfile)) {
        fprintf(stderr, "Empty hash file");
        exit(EXIT_FAILURE);
    }

    if (!readPasswords(&data, passwordFile)) {
        fprintf(stderr, "Empty password file");
        exit(EXIT_FAILURE);
    }

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

    //do I need to call my thread function here? 

    //join threads
    for (int i = 0; i < threadCount; ++i) {
        pthread_join(tids[i], NULL);
    }


    //print total summary

    //do I need to find a away to pass my time structs back to main?
    //do I need to display these?
    //do I need to use a for loop, and sum all the cracked, failed and totals for all threads in my threads array?
    //or is this information already calculated somewhere?
    fprintf(stderr, "total : %d    <4.47> sec cracked:     %d failed: %d total: %d", threadCount, /*time*/, /*cracked*/, /*failed*/, /*total*/);




    //clean, deallocate memory 
    pthread_mutex_destroy(&data.lock);

    for (int i = 0; i < data.hashCount; i++) {
        free(data.hashes[i]);
    }
    free(data.hashes);

    for (int i = 0; i < data.passwordCount; i++) {
        free(data.passwords[i]);
    }
    free(data.passwords);



    if (outFile) {
        close(outfd);
    }
     
    return EXIT_SUCCESS;
}


// Desc:
// Inputs:
// Return:
void *threadFunction(void * thread) {
    
    int index = 0;
    int cracked = 0;
    //is this the right way to allocate memory for this variable?
    //ALL memory needs to be dynamically allocated
    char * salt = malloc(3 * sizeof(char));
    char * result;
    struct crypt_data cdata;
    struct timeval start, end;

    gettimeofday(&start, NULL);

    cdata.initialized = 0;

     
    // start infnite loop 
    while (1) {

        //protect shared counter, cannot access shared resource unless unlocked
        pthread_mutex_lock(&thread->shared->lock);

        index = thread->shared->nextHash;
        ++thread->shared->nextHash;

        //iterate to next hash within mutex
        pthread_mutex_unlock(&thread->shared->lock);

        if (index >= thread->shared->hashCount)
            break;

        cracked = 0;

        //run cracking loop for all passwords, while thread is not cracked
        for (int p = 0; p < thread->shared->passwordCount && !cracked; ++p) {
            //char *password = shared->passwords[p];

            //loop through all possible salts
            //consider replaced 64 with defined macro
            for (int i = 0; i < 64 && !cracked; ++i) {
                
                for(int j = 0; j < 64; ++j) {
                    //generate next possible salt 
                    salt[0] = SALT[i];
                    salt[1] = SALT[j];
                    salt[2] = '\0';

                    result = crypt_rn(thread->shared->passwords[p], salt, &cdata, sizeof(cdata));

                    //check if this password + salt cracked the hash
                    if (strcmp(result, thread->shared->hashes[index]) == 0) {

                        //use mutex when printing result 
                        pthread_mutex_lock(&thread->shared->lock);
                        printf("cracked: %s : %s\n", thread->shared->hashes[index], thread->shared->passwords[p]);
                        pthread_mutex_unlock(&thread->shared->lock);

                        //interate this thread's number of cracked passwords
                        //good boy. 
                        ++thread->cracked;
                        cracked = 1;
                        break;
                    }
                }

            }
        }

        //check if the thread failed to crack the hash
        if (!cracked) {
            //use mutex when printing result 
            pthread_mutex_lock(&thread->shared->lock);
            printf("*** failed: %s\n", thread->shared->hashes[index]);
            pthread_mutex_unlock(&thread->shared->lock);

            //iterate this threads number of failures
            //L for thread
            ++thread->failed;
        }

        ++thread->total;
    }

    // compute time difference
    gettimeofday(&end, NULL);


    free(salt);

    pthread_exit(NULL);


    //might need to fix output format entirely
    //sent to stderr
    //thread: 2 3.80 sec cracked: 5 failed: 1 total: 6
    //or is this format printed at the bottom after time has been calculated?
    //fprintf(stderr, "thread: " " sec cracked:" 5 "failed: " " total: " , thread id, time, cracked, failed, total);


}



// Desc:
// Inputs:
// Return:
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

// Desc:
// Inputs:
// Return:
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



 