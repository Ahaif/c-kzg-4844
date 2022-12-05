#include <time.h>
#include <stdlib.h>
#include "c_kzg_4844.h"

int main() {

    float startTime = (float)clock()/CLOCKS_PER_SEC;

    KZGSettings *kzgsettings = (KZGSettings*)malloc(sizeof(KZGSettings));

    FILE *kzg_settings_file = fopen("trusted_setup.txt", "r");

    load_trusted_setup(kzgsettings, kzg_settings_file);

    fclose(kzg_settings_file);

    float endTime = (float)clock()/CLOCKS_PER_SEC;

    float timeElapsed = (endTime - startTime) * 1000;

    printf("Elapsed time to load setup %.03f ms\n", timeElapsed);

    Blob blob;
    KZGCommitment commitment;

    for(int i=0; i < 4096*32; i++) {
        blob[i] = i;
    }


    startTime = (float)clock()/CLOCKS_PER_SEC;

    for(int i=0; i < 1000; i++) {
        blob_to_kzg_commitment(&commitment, blob, kzgsettings);
    }

    endTime = (float)clock()/CLOCKS_PER_SEC;

    timeElapsed = (endTime - startTime) * 1000;

    printf("Elapsed time to compute blob commitment %.03f ms\n", timeElapsed);
    printf("Average time %.03f ms\n", timeElapsed / 1000);

    uint8_t zero[BYTES_PER_FIELD_ELEMENT];

    startTime = (float)clock()/CLOCKS_PER_SEC;

    for(int i=0; i < 1000; i++) {
        bool ret;
        verify_kzg_proof(&ret, &commitment, zero, zero, &commitment, kzgsettings);
    }

    endTime = (float)clock()/CLOCKS_PER_SEC;

    timeElapsed = (endTime - startTime) * 1000;

    printf("Elapsed time to verify kzg proofs %.03f ms\n", timeElapsed);
    printf("Average time %.03f ms\n", timeElapsed / 1000);


    free_trusted_setup(kzgsettings);
}