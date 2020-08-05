//
//  main.c
//  lilcryptoc
//
//  Created by Patrik Nusszer on 2020. 07. 26..
//  Copyright © 2020. Patrik Nusszer. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>

size_t fsize(const char * file) {
    struct stat64 stats;
    stat64(file, &stats);
    return stats.st_size;
}

void xorcodebeta(const char * filep, const char * keyp, const char * outp, unsigned int chunksz, _Bool xnor) {
    if (fsize(filep) == 0 || fsize(keyp) == 0)
        return;
    
    FILE * file = fopen(filep, "r");
    FILE * key = fopen(keyp, "r");
    size_t ksz = fsize(filep);
    FILE * chip = fopen(outp, "w");
    
    char *fchunk = (char*)malloc(sizeof(char) * chunksz);
    char *kchunk = (char*)malloc(sizeof(char) * chunksz);
    
    int rfchunksz, rkchunksz, fchunki, kchunki;
    rfchunksz = rkchunksz = fchunki = kchunki = 0;
    
    rfchunksz = (int)fread(fchunk, sizeof(char), chunksz, file);
    rkchunksz = (int)fread(kchunk, sizeof(char), chunksz, key);
    
    do {
        fchunk[fchunki] ^= kchunk[kchunki];
        
        if (xnor)
            fchunk[fchunki] = ~fchunk[fchunki];
        
        fchunki = (fchunki + 1) % rfchunksz;
        kchunki = (kchunki + 1) % rkchunksz;
        
        if (fchunki == 0) {
            fwrite(fchunk, sizeof(char), rfchunksz, chip);
            rfchunksz = (int)fread(fchunk, sizeof(char), chunksz, file);
            
            if (rfchunksz == 0)
                break;
        }
        
        if (kchunki == 0 && ksz > chunksz) {
            rkchunksz = (int)fread(kchunk, sizeof(char), chunksz, key);
            
            if (rkchunksz == 0) {
                fseek(key, 0, SEEK_SET);
                rkchunksz = (int)fread(kchunk, sizeof(char), chunksz, key);
            }
            else if (rkchunksz != chunksz)
                fseek(key, 0, SEEK_SET);
        }
    } while (1);
    
    fflush(chip);
    fclose(chip);
    fclose(file);
    fclose(key);
}

void keyget(FILE * f, size_t fsz, unsigned int chunksz, char *chunk, size_t offset) {
    if (offset != -1)
        fseek(f, 0, SEEK_SET);
    
    unsigned int read = (unsigned int)fread(chunk, sizeof(char), chunksz, f);
    chunksz -= read;
    
    if (chunksz != 0) {
        fseek(f, 0, SEEK_SET);
        unsigned int wholeTimes = chunksz / fsz;
        char key[fsz];
        
        if (wholeTimes > 0) {
            fread(key, sizeof(char), fsz, f);
            
            for (unsigned int i = 0; i < wholeTimes; i++) {
                memcpy(chunk + read + (i * fsz), key, fsz);
                chunksz -= fsz;
            }
        }
        
        fseek(f, 0, SEEK_SET);
        fread(key, sizeof(char), chunksz, f);
        memcpy(chunk + read + (wholeTimes * fsz), key, chunksz);
    }
}

void xorcode(const char * filep, const char * keyp, const char * outp, unsigned int chunksz, _Bool xnor) {
    size_t fsz = fsize(filep);
    size_t ksz = fsize(keyp);
    
    if (fsz == 0 || ksz == 0)
        return;
    
    FILE * file = fopen(filep, "r");
    FILE * key = fopen(keyp, "r");
    FILE * chip = fopen(outp, "w");
    
    char *fchunk = (char*)malloc(sizeof(char) * chunksz);
    char *kchunk = (char*)malloc(sizeof(char) * chunksz);
    
    do {
        unsigned int read = (unsigned int)fread(fchunk, sizeof(char), chunksz, file);
        
        if (read == 0)
            break;
        
        keyget(key, ksz, read, kchunk, -1);
        
        for (unsigned int i = 0; i < read; i++) {
            fchunk[i] ^= kchunk[i];
            
            if (xnor)
                fchunk[i] = ~fchunk[i];
        }
        
        fwrite(fchunk, sizeof(char), read, chip);
    } while (1);
    
    
    fflush(chip);
    fclose(chip);
    fclose(file);
    fclose(key);
}

void gen(const char * path, size_t bytes) {
    FILE * f = fopen(path, "w");
    srand(time(0));
    int buffer;
    
    for (size_t i = 0; i < bytes / sizeof(int); i++) {
        buffer = rand();
        fwrite(&buffer, sizeof(int), 1, f);
    }
    
    int rem = bytes % sizeof(int);
    
    if (rem != 0) {
        buffer = rand();
        fwrite(&buffer, sizeof(char), rem, f);
    }
    
    fflush(f);
    fclose(f);
}

int main(int argc, const char * argv[]) {
    if (argc == 1) {
        char filep[257];
        char buff[257];
        printf("File: ");
        fgets(filep, 256, stdin);
        sscanf(filep, "%s", filep);
        printf("(keygen/crypt): ");
        fgets(buff, 256, stdin);
        sscanf(buff, "%s", buff);
        
        if (strcmp(buff, "crypt") == 0) {
            printf("Key: ");
            char keyp[257];
            fgets(keyp, 256, stdin);
            sscanf(keyp, "%s", keyp);
            printf("Output: ");
            char outp[257];
            fgets(outp, 256, stdin);
            sscanf(outp, "%s", outp);
            unsigned int chunksz;
            printf("Chunk size: ");
            fgets(buff, 256, stdin);
            sscanf(buff, "%ud", &chunksz);
            printf("xor (or xnor)?: ");
            char array[10];
            fgets(array, 9, stdin);
            int x;
            sscanf(array, "%d", &x);
            xorcode(filep, keyp, outp, chunksz, ~x);
        }
        else {
            printf("Bytes: ");
            fgets(buff, 256, stdin);
            size_t bytes;
            sscanf(buff, "%zu", &bytes);
            gen(filep, bytes);
        }
    }
    else {
        if (strcmp(argv[2], "crypt") == 0) {
            unsigned int chunksz;
            sscanf(argv[5], "%ud", &chunksz);
            int xor;
            sscanf(argv[6], "%d", &xor);
            xorcode(argv[1], argv[3], argv[4], chunksz, xor);
        }
        else {
            size_t bytes;
            sscanf(argv[2], "%zu", &bytes);
            gen(argv[1], bytes);
        }
    }
    
    return 0;
}
