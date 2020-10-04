/*  
    HGU 2020-02 Computer Security HW01: DES
    Author: JJM
*/
#include "des.h"

unsigned long long plaintext = 0x123456ABCD132536;
unsigned long long key = 0xAABB09182736CCDD;
unsigned long long IP_text = 0;
unsigned long long LPT = 0;
unsigned long long RPT = 0;
unsigned long long cipherKey = 0;
unsigned long long cipherKey28L = 0;
unsigned long long cipherKey28R = 0;
unsigned long long shifted28L[16] = {0, };
unsigned long long shifted28R[16] = {0, };
unsigned long long shifted56Key[16] = {0, };
unsigned long long roundKey[16] = {0, };
unsigned long long Left[17] = {0, };
unsigned long long Right[17] = {0, };
unsigned long long combinedLR = 0;
unsigned long long ciphertext = 0;


void setIPtext(){
    int plain_idx = 0;

    for(int i=0; i<64; i++){
        // initial_permutation[i] 번째 bit는 plaintext[plain_idx] 이다.
        plain_idx = initial_permutation[i] - 1;

        // plaintext의 plain_idx번째 비트가 1이라면,
        if(plaintext AND (mask64 >> plain_idx)){
            IP_text = IP_text OR (mask64 >> i);
        }
        else{
            // 초기값이 0이기 때문에 0일 때에는 따로 처리 안함
        }
    }
}

void decomposeIPText(){
    LPT = IP_text >> 32;
    RPT = IP_text % mask33;

    Left[0] = LPT;
    Right[0] = RPT;
}

void keyTranf64to56(){
    // set IP text와 같은 방식
    int key_idx = 0;

    for(int i=0; i<56; i++){
        key_idx = parity_drop[i] - 1;
        if(key AND (mask64 >> key_idx)){
            cipherKey = cipherKey OR (mask64 >> i);
        }
    }
    // 64bit가 아니라 56bit 라서
    cipherKey = cipherKey >> 8;
}
void cipherKey56to28(){
    cipherKey28L = cipherKey >> 28;
    cipherKey28R = cipherKey % mask29;
}
void compressP_box(int currRound){
    int compression_idx = 0;
    for(int i=0; i<48; i++){
        compression_idx = compression_table[i] - 1;

        if(shifted56Key[currRound] AND (mask56 >> compression_idx)){
            roundKey[currRound] = roundKey[currRound] OR (mask56 >> i);
        }
    }
    // 56 bits가 아니라 48 bits 라서
    roundKey[currRound] = roundKey[currRound] >> 8;
}
void keyGeneration(){
    // key --> parityDrop (64 -> 56 bits)
    keyTranf64to56();

    // 56 -> 28 bits
    cipherKey56to28();

    // circular shift left along rounds
    int shiftLeftBit = 0;
    for(int i=0; i<16; i++){
        shiftLeftBit += bitShift_along_round[i];

        // circular shift left
        shifted28L[i] = ((cipherKey28L << shiftLeftBit) % mask29) OR (cipherKey28L >> (28 - shiftLeftBit));
        shifted28R[i] = ((cipherKey28R << shiftLeftBit) % mask29) OR (cipherKey28R >> (28 - shiftLeftBit));
        
        // 28+28 = 56
        shifted56Key[i] = shifted28L[i] << 28;
        shifted56Key[i] = shifted56Key[i] OR shifted28R[i];

        // compression P-Box ()
        compressP_box(i);

        // print round key
        // printf("[round key %02d]: %#llx\n", i, roundKey[i]);
    }
}

unsigned long long des(int round){
    unsigned long long result = 0;
    unsigned long long tmpResult = 0;

    // expansion P-box
    int Right_idx = 0;
    for(int i=0; i<48; i++){
        Right_idx = expansion_pbox[i] - 1;

        if(Right[round] AND (mask32 >> Right_idx)){
            result = result OR (mask48 >> i);
        }
    }

    // XOR
    // printf("\troundKey(=0x%016llx) XOR result(=0x%016llx) = 0x%016llx\n", roundKey[round], result, roundKey[round] XOR result);
    result = result XOR roundKey[round];

    // S-Box: 
    // i번째 비트는 i번째 s-box 쓰기
    unsigned long long tmp6Bit = 0;
    unsigned long long row = 0;
    unsigned long long col = 0;
    for(int i=0; i<8; i++){
        tmp6Bit = (result >> (48 - (i + 1) * 6)) % 0x40;

        row = ((tmp6Bit >> 5) << 1) OR (tmp6Bit % 0x2);
        col = (tmp6Bit >> 1) % 0x10;

        tmpResult = (tmpResult << 4) OR sbox[i][col][row];
    }
    result = tmpResult;

    // Straight P-box
    int result_idx = 0;
    tmpResult = 0;
    for(int i=0; i<32; i++){
        result_idx = straight_pbox[i] - 1;

        if(result AND (mask32 >> result_idx)){
            tmpResult = tmpResult OR (mask32 >> i);
        }
    }
    result = tmpResult;
    
    return result;
}

void doFinalPermutation(){
    int combined_idx = 0;

    for(int i=0; i<64; i++){
        combined_idx = final_permutation[i] - 1;

        if(combinedLR AND (mask64 >> combined_idx)){
            ciphertext = ciphertext OR (mask64 >> i);
        }
    }
}

int main(){
    // Step01: Plain text (64 bits)
    int mode = -1;
    printf("< DES Encription Algorithm >\n[1]: plaintext, key from user Input\n[2]: plaintext, key from default value\n");
    scanf("%d", &mode);
    if(mode == 1){
        printf("Please input PLAINTEXT and KEY\n");
        scanf("%llx %llx", &plaintext, &key);
    }
    printf("\n[plaintext]: %#llx\n[key]: %#llx\n", plaintext, key);

    // Step02: Initial Permutation 
    setIPtext();
    printf("[IP_text]: %#llx\n", IP_text);

    // Step03: LPT RPT
    decomposeIPText();
    printf("\t[LPT]: %#llx\n\t[RPT]: %#llx\n", LPT, RPT);

    // Key generation
    keyGeneration();

    // Step04: 16 rounds
    unsigned long long afterDES = 0;
    for(int round = 0; round < 16; round++){
        // Round (in: Left[i], Right[i]/ out: Left[i+1], Right[i+1])
        printf("[Round %02d]\n\tRound Key: %#llx, Left[%02d]: %#llx, Right[%02d]: %#llx\n", round+1, roundKey[round], round, Left[round], round, Right[round]);

        // Mixer
        afterDES = des(round);
        printf("\tAfter DES: %#llx\n", afterDES);

        // XOR
        afterDES = afterDES XOR Left[round];

        // Swapper (마지막은 스왚 안함)
        if(round != 15){
            Left[round+1] = Right[round];
            Right[round+1] = afterDES;
        }else{
            Left[round+1] = afterDES;
            Right[round+1] = Right[round];
        }
        printf("\tLeft[%02d]: %#llx\n\tRight[%02d]: %#llx\n\n", round+1, Left[round+1], round+1, Right[round+1]);
    }

    // Combine Left + Right
    combinedLR = (Left[16] << 32) OR Right[16];
    printf("combined L + R: %#llx\n", combinedLR);

    // Step05: Final Permuatation
    doFinalPermutation();

    // Step06: Ciphertext(64 bits)
    printf("[Ciphertext]: %#llx\n", ciphertext);
}