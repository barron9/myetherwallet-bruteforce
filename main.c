#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include <time.h>
#include <string.h>
#include "sha3.h"

int main(void) {
    clock_t start_t, end_t;
    
    if (sodium_init() < 0) {
    }
    uint8_t chars [] = {
        0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x44,
        0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,0x7A
    };
    uint8_t numbs [] ={
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39
    };
    uint8_t  passw[20] = {0x44.....0x33};
  uint8_t salt[32] = {
            0x47,.....0xc1};
        uint8_t ciper[32]={
            0x7e,.....0x09
            
        };
     while(1){
        start_t = clock();
        printf("--start--:");
     
        passw[6]++;
        printf("%s",passw);
        uint8_t data2[64] ;
        
        crypto_pwhash_scryptsalsa208sha256_ll((const uint8_t *) passw, sizeof(passw), (const uint8_t *) salt, 32, 262144U, 8U, 1U, (uint8_t *)data2, 32);
        
      //  printf("\ncrypto_pwhash_scryptsalsa208sha256_ll : \n");
        register_t yyx;
        register_t derivedkey[32];
        for(yyx=0;yyx<32;yyx++){
            derivedkey[yyx]=data2[yyx];
            //printf("%02x",data2[yyx]);
        }
        register_t presha3[48];
        const register_t *hash;
        
        
        memcpy(&presha3[0], &data2[16],16);
        memcpy(&(presha3[16]),&ciper,32);
        
        
#ifdef SHA3_USE_KECCAK
        sha3_context c;

        sha3_Init256(&c);
        sha3_Update(&c, presha3, 48);
        
        hash = sha3_Finalize(&c);
        
        register_t st;
        //printf("\nhash : \n");
        for(st=0;st<32;st++){
            
           // printf("%02x",hash[st]);
            
        }
        if(memcmp(hash, "\x05\.....xcb", 32) != 0) {
            printf("->wrong pass");
        }
        else{            printf("->pass found");
break;}
        
#endif
        end_t = clock();
        printf("::--end--%ld\n", (end_t-start_t));
        
    }
    return 0;
}
