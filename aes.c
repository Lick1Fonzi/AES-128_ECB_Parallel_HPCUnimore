#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include<omp.h>
#include<sys/time.h>

/*
 * AES-128
 * https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf 
 */

int BLOCKSIZE = 16; // 16 bytes == 128 bits
int NROUNDS = 10;
int KEYSIZE = 16; // for simplicity, i will always use blocksize as KEYSIZE == BLOCKSIZE in AES-128

char key_test[] = "YELLOW SUBMARINE"; // https://cryptopals.com/sets/1/challenges/7 

long long timeInMilliseconds(void) {
    struct timeval tv;

    gettimeofday(&tv,NULL);
    return (((long long)tv.tv_sec)*1000)+(tv.tv_usec/1000);
}

//--------------------------- From wikipedia, generation of S-box ---------------------------------
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))

void initialize_aes_sbox(uint8_t sbox[256]) {
	uint8_t p = 1, q = 1;
	
	/* loop invariant: p * q == 1 in the Galois field */
	do {
		/* multiply p by 3 */
		p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);

		/* divide q by 3 (equals multiplication by 0xf6) */
		q ^= q << 1;
		q ^= q << 2;
		q ^= q << 4;
		q ^= q & 0x80 ? 0x09 : 0;

		/* compute the affine transformation */
		uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);

		sbox[p] = xformed ^ 0x63;
	} while (p != 1);

	/* 0 is a special case since it has no inverse */
	sbox[0] = 0x63;
}
uint8_t SBOX[256];
// -------------------------------------------------------------------------------------------------

/*
 * Function to convert ascii strings in corresponding bytes hex strings
 * To view non printable chars, for testing purposes
 */ 
char *ascii_to_hex(char s[]){
    char hexchars[] = "0123456789abcdef";
    int len = strlen(s);
    char* tmp = (char *) malloc((len * 2) + 1);
    tmp[0] = '\0';
    int j = 0;
    for(int i = 0; i < len; i++){
        char c = s[i];
        int dec = (int)c / 16;
        int unit = (int) c - (dec * 16);
        tmp[j++] = hexchars[dec];
        tmp[j++] = hexchars[unit];
    }
    tmp[j] = '\0';
    return tmp;
}

/*
 * Left rotate word: wi = [a0 a1 a2 a3] -> [a1 a2 a3 a0]  where aX is a byte
 */
void RotWord(uint8_t w[]){
    int lenword = 4;
    uint8_t prev = w[0];
    for(int i = lenword - 1; i >= 0; i--){
        uint8_t tmp = w[i];
        w[i] = prev;
        prev = tmp;
    }
}

/*
 * Apply s-box permutation to 4 bytes word: wi = [a0 a1 a2 a3] -> [b0 b1 b2 b3]
 */
void SBoxWord(uint8_t w[]){
    int lenword = 4;
    for(int i = 0; i < lenword; i++){
        w[i] = (uint8_t)SBOX[w[i]];
    }
}

// Round constant for key scheduling alg. It is 2^i-1 mod 2^8, i=number of round. 
uint8_t RC[] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
/*
 * Xor first byte with round constant
 */
void Rcon(uint8_t w[], int round){
    int lenword = 4;
    w[0] ^= RC[round];
}

/*
 * Xor two same-size array of bytes
 */
void XOR(uint8_t s1[], uint8_t s2[],int len){
    for(int i = 0; i < len; i++){
        s1[i] ^=  s2[i];
    }
}

/*
 * Prints hex values, debug purposes
 */
void print_hex(uint8_t prev[], int l){
    for (int j = 0; j < l; j++) {
        printf("%02x", prev[j]);
    }
    printf("\n");
}

/*
 * Algorithm to derive subkeys for every round
 * Explained here: https://braincoke.fr/blog/2020/08/the-aes-key-schedule-explained/#key-expansion 
 */
void key_schedule(uint8_t k[][BLOCKSIZE]){
    int nk = 4; // every subkey is permutated considering pieces of nk bytes words and the previous subkey. K = [w0 w1 w2 w3]
    uint8_t last_subkey[BLOCKSIZE];
    uint8_t curr_subkey[BLOCKSIZE];
    for(int i = 1; i <= 10; i++){
        memcpy(last_subkey,k[i-1],BLOCKSIZE);
        //printf("Last subkey at round %d \n",i);
        //print_hex(last_subkey,BLOCKSIZE);
        for(int j = 0; j < 4; j++){
            uint8_t prev[4];
            uint8_t four_prev[4];
            if(j == 0){
                memcpy(prev, last_subkey + (nk * 3), 4);
                //printf("wi-1, rotated, sboxed, rconned\n");
                //print_hex(prev,4);
                RotWord(prev);
                //print_hex(prev,4);
                SBoxWord(prev);
                //print_hex(prev,4);
                Rcon(prev,i);
                //print_hex(prev,4);
            }
            else{
                memcpy(prev, curr_subkey + (nk * (j-1)),4);
                //printf("wi-1\n");
                //print_hex(prev,4);
            }
            //printf("w1-4 and final xor\n");
            memcpy(four_prev, last_subkey + (nk * j),4);
            //print_hex(four_prev,4);
            XOR(prev,four_prev,4);
            //print_hex(prev,4);
            memcpy(curr_subkey + (nk * j),prev,4);
            //printf("At end of w%d, curr subkey is: \n",j);
            //print_hex(curr_subkey,BLOCKSIZE);
        }
        memcpy(k[i],curr_subkey,BLOCKSIZE);
    }
    return;
}

/*
 * Pad text to multiple of BLOCKSIZE, using PKCS7
 */
void pad(uint8_t* plainpadded, int lentext, int npad, int padded_size){
    printf("blocksize: %d text: %d pad: %d tot: %d \n",BLOCKSIZE, lentext,npad,padded_size);
    for(int i = lentext; i < padded_size; i++){
        plainpadded[i] = npad;
        //plainpadded[i] = 0;   // ZERO PADDING
    }
    return;
}

/*
 * Apply s-box permutation to all bytes of one block
 */
void SubBytes(uint8_t block[]){
    for(int i = 0; i < BLOCKSIZE; i++){
        block[i] = SBOX[block[i]];
    }
}

/*
 * Shift i-th word i-1 times
 */
void ShiftRows(uint8_t w[]){
    for(int i = 0; i < 4; i++){
        // bytes considerati sono le colonne in riga 
        uint8_t currw[4];
        for(int s = 0; s < 4; s++){
            currw[s] = w[i + (4*s)];
        }
        for(int j = 0; j < i; j++){
            RotWord(currw);
        }
        for(int s = 0; s < 4; s++){
            w[i + (4*s)] = currw[s];
        }
    }
}

/*
 * Constants for mixcolumns matrix multiplication
 */
uint8_t MIXMATRIX[][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02},
};

static uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

uint8_t gf_mult(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    while (b > 0) {
        if (b & 1) 
            p ^= a;
        a =  (a << 1) ^ (a & 0x80 ? 0x1b : 0); //called in paper xtime(a); modulo 0x1b only if MSB is 1, else is not needed
        b >>= 1;
    }
    return p;
}

/*
 * Apply Matrix multiplication in Galois Field 2^8 to a column of the state (that is, a word of the block)
 */
void MixColumns(uint8_t block[]){
    //print_hex(block,BLOCKSIZE);
    for(int i = 0; i < 4; i++){
        uint8_t currblock[4];
        uint8_t tmp[4];
        for(int s = 0; s < 4; s++){
            currblock[s] = block[(i*4) + s];
            tmp[s] = 0x00;
        }
        //print_hex(currblock,4);
        // MATRIX MULT
        for(int j = 0; j < 4; j++){
            for(int t = 0; t < 4; t++){
                tmp[j] ^= gf_mult(currblock[t],MIXMATRIX[j][t]);
            }
        }
        for(int s = 0; s < 4; s++){
            block[(i * 4) + s] = tmp[s];
        }
    }
    //print_hex(block,BLOCKSIZE);     
}


/*
 * Encrypt a block of plaintext, applying 10 rounds with ECB mode of operation
 */
void encrypt_ECB(uint8_t plain[], uint8_t key[][BLOCKSIZE]){
    
   // printf("round 0\n");
    uint8_t curr_block[BLOCKSIZE];
    XOR(plain,key[0],BLOCKSIZE); //this is the AddRoundKey func
    //print_hex(plain,nblocks*BLOCKSIZE);
    
    for(int r = 1; r < NROUNDS; r++){
        //printf("round: %d\n",r);
        //printf("Current block to plain: ");
        //print_hex(plain,BLOCKSIZE);
        SubBytes(plain);
        //printf("Current block sboxed: ");
        //print_hex(plain,BLOCKSIZE);
        ShiftRows(plain);
        //printf("Current block shiftedrows: ");
        //print_hex(plain,BLOCKSIZE);
        MixColumns(plain);
        //printf("Current block mixed columns: ");
        //print_hex(plain,BLOCKSIZE);
        XOR(plain,key[r],BLOCKSIZE);
    }
        //print_hex(plain,nblocks*BLOCKSIZE);

    //printf("Round 10\n");
    SubBytes(plain);
    ShiftRows(plain);
    XOR(plain,key[10],BLOCKSIZE);
    //print_hex(plain,nblocks*BLOCKSIZE);

}

int main(){
    long long start,stop,alg_start,alg_stop;
    start = timeInMilliseconds();
    printf("\n\n\n############### AES-128 CIPHER ################## \n");
    initialize_aes_sbox(SBOX);

    char key[] = "YELLOW SUBMARINE";

    FILE *f = fopen("./plain.txt","rb");
    if(f==NULL){
        printf("Error reading file");
        return 1;
    }
    fseek(f,0,SEEK_END);
    long lentext = ftell(f);
    rewind(f);
    //int lentext = BLOCKSIZE;
    long npad = (lentext % BLOCKSIZE) ? BLOCKSIZE - (lentext % BLOCKSIZE) : 0;
    long padded_size = lentext + npad;
    int blocks_to_cipher = padded_size / BLOCKSIZE;


    uint8_t *plaintext = (uint8_t *)malloc(padded_size);
    fread(plaintext,1,lentext,f);
    pad(plaintext, lentext, npad, padded_size);
    fclose(f);

    uint8_t KEY[11][BLOCKSIZE];
    for(int i = 0; i < BLOCKSIZE; i++){
        KEY[0][i] = (uint8_t) key[i];
    }

    printf("Chiave e plaintext: \n");
    print_hex(KEY[0],BLOCKSIZE);
    //print_hex(plaintext,padded_size);

    printf("Key schedule...\n");
    key_schedule(KEY);

    for(int i = 0;i < 11; i++){
        print_hex(KEY[i],BLOCKSIZE);
    }

    printf("Encrypting...\n");
    alg_start = timeInMilliseconds();
    #pragma omp parallel for 
    for(int i = 0; i < blocks_to_cipher; i++){
        encrypt_ECB(plaintext + (i*BLOCKSIZE),KEY);
    }
    alg_stop = timeInMilliseconds();
    //print_hex(plaintext,padded_size);
    printf("Total time: %lld s\n", (alg_stop - start)/1000);
    printf("Kernel time: %lld s\n",(alg_stop - alg_start) / 1000);
    printf("Non-kernel time: %lld s \n", ((alg_stop - start) - (alg_stop - alg_start)) / 1000 );
}
