#include<stdio.h>
#include<stdio.h>

#include<cuda_runtime.h>

#define NT 32
#define NB 4

#define BLOCKSIZE 16
#define NROUNDS 10
#define KEYSIZE 16
typedef unsigned char uint8_t;


uint8_t SBOX[256];
__constant__ uint8_t SBOXD[256];
#define ROTL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
__host__ void initialize_aes_sbox(uint8_t sbox[256]) {
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

/*
 * Left rotate word: wi = [a0 a1 a2 a3] -> [a1 a2 a3 a0]  where aX is a byte
 */
__host__ void RotWord(uint8_t w[]){
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
__host__ void SBoxWord(uint8_t w[]){
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
__host__ void Rcon(uint8_t w[], int round){
    int lenword = 4;
    w[0] ^= RC[round];
}

/*
 * Xor two same-size array of bytes
 */
__host__ void XOR(uint8_t s1[], uint8_t s2[],int len){
    for(int i = 0; i < len; i++){
        s1[i] ^=  s2[i];
    }
}

/*
 * Prints hex values, debug purposes
 */
__host__ void print_hex(uint8_t prev[], int l){
    for (int j = 0; j < l; j++) {
        printf("%02x", prev[j]);
    }
    printf("\n");
}

__device__ void print_hex_d(uint8_t prev[], int l){
    for (int j = 0; j < l; j++) {
        printf("%02x", prev[j]);
    }
    printf("\n");
}

__host__ void key_schedule(uint8_t k[][BLOCKSIZE]){
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
__host__ void pad(uint8_t* plainpadded, int lentext, int npad, int padded_size){
    printf("blocksize: %d text: %d pad: %d tot: %d \n",BLOCKSIZE, lentext,npad,padded_size);
    for(int i = lentext; i < padded_size; i++){
        plainpadded[i] = npad;
        //plainpadded[i] = 0;   // ZERO PADDING
    }
    return;
}


__device__ void RotWordD(uint8_t w[]){
    int lenword = 4;
    uint8_t prev = w[0];
    for(int i = lenword - 1; i >= 0; i--){
        uint8_t tmp = w[i];
        w[i] = prev;
        prev = tmp;
    }
}

__device__ void XORD(uint8_t *s1, uint8_t *s2,int len){
    for(int i = 0; i < len; i++){
        s1[i] ^=  s2[i];
    }
}

/*
 * Apply s-box permutation to all bytes of one block
 */
__device__ void SubBytes(uint8_t block[]){
    for(int i = 0; i < BLOCKSIZE; i++){
        block[i] = SBOXD[block[i]];
    }
}

/*
 * Shift i-th word i-1 times
 */
__device__ void ShiftRows(uint8_t w[]){
    for(int i = 0; i < 4; i++){
        // bytes considerati sono le colonne in riga 
        uint8_t currw[4];
        for(int s = 0; s < 4; s++){
            currw[s] = w[i + (4*s)];
        }
        for(int j = 0; j < i; j++){
            RotWordD(currw);
        }
        for(int s = 0; s < 4; s++){
            w[i + (4*s)] = currw[s];
        }
    }
}

/*
 * Constants for mixcolumns matrix multiplication
 */
__constant__ uint8_t MIXMATRIX[16] = {
    0x02, 0x03, 0x01, 0x01,
    0x01, 0x02, 0x03, 0x01,
    0x01, 0x01, 0x02, 0x03,
    0x03, 0x01, 0x01, 0x02,
};

__device__ void gf_mult(uint8_t a, uint8_t b,uint8_t *x) {
    uint8_t p = 0;
    while (b > 0) {
        if (b & 1) 
            p ^= a;
        a =  (a << 1) ^ (a & 0x80 ? 0x1b : 0); //called in paper xtime(a); modulo 0x1b only if MSB is 1, else is not needed
        b >>= 1;
    }
    *x = p;
}

/*
 * Apply Matrix multiplication in Galois Field 2^8 to a column of the state (that is, a word of the block)
 */
__device__ void MixColumns(uint8_t block[]){
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
	    	uint8_t x; 
		gf_mult(currblock[t],MIXMATRIX[(j * 4) + t],&x);     
		tmp[j] ^= x;
            }
        }
        for(int s = 0; s < 4; s++){
            block[(i * 4) + s] = tmp[s];
        }
    }
    //print_hex(block,BLOCKSIZE);     
}

__constant__ uint8_t KEYD[16*11];
__global__ void encryptFull_ECB(uint8_t *plain, int nblocks){
	int tindex = threadIdx.x + blockIdx.x * blockDim.x;
	int stride = blockDim.x * gridDim.x;
    //printf("thread %d :round 0\n",threadIdx.x + blockIdx.x * blockDim.x);	
    for(int i = tindex; i < nblocks; i += stride){
        XORD(plain + i*BLOCKSIZE ,KEYD,BLOCKSIZE); //this is the AddRoundKey func
    }
    //print_hex_d(plain,nblocks*BLOCKSIZE);
    
    for(int r = 1; r < NROUNDS; r++){
        //printf("round: %d\n",r);
        for(int i = tindex; i < nblocks; i += stride){
            uint8_t *curr_block = plain + i *BLOCKSIZE;
            //printf("Current block to plain: ");
            //print_hex_d(curr_block,BLOCKSIZE);
            SubBytes(curr_block);
            //printf("Current block sboxed: ");
            //print_hex_d(curr_block,BLOCKSIZE);
            ShiftRows(curr_block);
            //printf("Current block shiftedrows: ");
            //print_hex_d(curr_block,BLOCKSIZE);
            MixColumns(curr_block);
            //printf("Current block mixed columns: ");
            //print_hex_d(curr_block,BLOCKSIZE);
	    //printf("Xored with: ");
	    //print_hex_d(KEYD + (r * 16),BLOCKSIZE);
            XORD(curr_block,KEYD + (r * 16),BLOCKSIZE);
        }
        //print_hex_d(plain,nblocks*BLOCKSIZE);
    }

    //printf("Round 10\n");
    for(int i = tindex; i < nblocks; i += stride){
        uint8_t *curr_block = plain + i *BLOCKSIZE;
        SubBytes(curr_block);
        ShiftRows(curr_block);
        XORD(curr_block,KEYD + (10 * 16),BLOCKSIZE);
    }
	//print_hex_d(plain,nblocks*BLOCKSIZE);
}
uint8_t *plain_d;
int main(){

	cudaEvent_t start,stop,alg_start,alg_stop;
	float tot_t,alg_t;
	cudaEventCreate(&start);
	cudaEventCreate(&alg_start);
	cudaEventCreate(&alg_stop);
	cudaEventCreate(&stop);
	cudaEventRecord(start);

	FILE *f = fopen("./plain.txt","rb");
    	if(f==NULL){
       		printf("Error reading file");
       		return 1;
    	}
    	fseek(f,0,SEEK_END);
    	long lentext = ftell(f);
    	rewind(f);
    	long npad = (lentext % BLOCKSIZE) ? BLOCKSIZE - (lentext % BLOCKSIZE) : 0;
    	long padded_size = lentext + npad;
	uint8_t *plaintext = (uint8_t *)malloc(padded_size);
    	fread(plaintext,1,lentext,f);
    	pad(plaintext, lentext, npad, padded_size);
	int blocks_to_cipher = padded_size / BLOCKSIZE;
    	fclose(f);
	//print_hex(plaintext,padded_size);

	cudaError err;
	initialize_aes_sbox(SBOX);
	err = cudaMemcpyToSymbol(SBOXD,SBOX,sizeof(uint8_t)*256);
	if (err != cudaSuccess) {
    		printf("MemcpyToSymbol of sbox failed: %s\n", cudaGetErrorString(err));
	}
	char key[] = "YELLOW SUBMARINE";
	uint8_t KEY[11][BLOCKSIZE];
    	for(int i = 0; i < BLOCKSIZE; i++){
		KEY[0][i] = (uint8_t) key[i];
    	}
	printf("Key schedule...\n");
	key_schedule(KEY);
	for(int i = 0;i < 11; i++){
        print_hex(KEY[i],BLOCKSIZE);
    	}
    uint8_t tmp[16*11];
	for(int i = 0; i < 11; i++){
		for(int j = 0; j < 16; j++){
			tmp[i*16 + j] = KEY[i][j];
		}
	}
	err = cudaMemcpyToSymbol(KEYD,tmp,sizeof(uint8_t)*16*11);
	if (err != cudaSuccess) {
		printf("MemcpyToSymbol of key failed: %s\n", cudaGetErrorString(err));
	}
	err = cudaMalloc(&plain_d,sizeof(uint8_t) * padded_size);
	if (err != cudaSuccess) {
    		printf("cudaMalloc of plain failed: %s\n", cudaGetErrorString(err));
	}
	err = cudaMemcpy(plain_d, plaintext, sizeof(uint8_t) * padded_size, cudaMemcpyHostToDevice);
	if (err != cudaSuccess) {
    		printf("cudaMemcpy of plain failed: %s\n", cudaGetErrorString(err));
	}
	int thread_n = 256;
	int blocks_pergrid = (blocks_to_cipher + thread_n - 1) / thread_n;
	printf("Blocks: %d\n",blocks_pergrid);
	cudaEventRecord(alg_start);
	encryptFull_ECB<<<blocks_pergrid,thread_n>>>(plain_d,blocks_to_cipher);
	if (err != cudaSuccess) {
    	printf("CUDA kernel launch failed: %s\n", cudaGetErrorString(err));
	}
	cudaDeviceSynchronize();
	cudaEventRecord(alg_stop);
	printf("kernel completed...\n");	
	uint8_t *result = (uint8_t*) malloc(sizeof(uint8_t) * padded_size);
	err = cudaMemcpy(result, plain_d, sizeof(uint8_t) * padded_size,cudaMemcpyDeviceToHost);
	if (err != cudaSuccess) {
    		printf("Memcpy of result failed: %s\n", cudaGetErrorString(err));
	}
	//print_hex(result,padded_size);
	cudaEventRecord(stop);
	cudaEventElapsedTime(&tot_t,start,stop);
	cudaEventElapsedTime(&alg_t,alg_start,alg_stop);
	printf("Total time: %f s\n",tot_t / 1000.0f);
	printf("Kernel execution time: %f s\n",alg_t / 1000.0f);
	printf("Non-kernel exection time: %f s\n",(tot_t - alg_t) / 1000.0f);	
	cudaDeviceReset();
	return 0;
}

