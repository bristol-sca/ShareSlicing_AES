

#include <scale/scale.h>
#include "bs.h"
#include "aes_rng.h"

#define BLOCK_NUM 8   //how many AES run in parallel
#define x BLOCK_NUM*4

void aesm_ecb_encrypt(uint8_t * outputb, uint8_t * inputb, uint8_t * key)
{
    int i,j;
    word_t input_space[BLOCK_SIZE];//128 bits as 128 words
    uint8_t blockrepeat=(uint8_t)scale_uart_rd(SCALE_UART_MODE_BLOCKING);
    memset(input_space,0,BS_BLOCK_SIZE);//zero the whole input space
    //for each block
    for(i = 0; i < 4*BLOCK_NUM; i += 4)  //here 4 is number of shares
    {

       if(i>=4*blockrepeat)// Random Blocks
        memmove(input_space + (i * WORDS_PER_BLOCK), prng(0), BLOCK_SIZE/8);
       else//Real Plaintext
        memmove(input_space + (i * WORDS_PER_BLOCK), inputb, BLOCK_SIZE/8);
        for(j=1;j<4;j++)
          memmove(input_space + ((i+j) * WORDS_PER_BLOCK),prng(0), BLOCK_SIZE/8);//16block of mask

        for (j = 0; j < WORDS_PER_BLOCK; j++)
        {
            input_space[ i * WORDS_PER_BLOCK + j] ^= input_space[ (i+1) * WORDS_PER_BLOCK + j]^input_space[ (i+2) * WORDS_PER_BLOCK + j]^input_space[ (i+3) * WORDS_PER_BLOCK + j];//first halve become p^m1^m2^m3
        }   //  |p^m1^m2^m3|m1|m2|m3|... p:certain byte of plaintext  
    }

    //scale_gpio_wr( SCALE_GPIO_PIN_TRG, true  );
    bs_cipher(input_space, key);//Core encryption
    //scale_gpio_wr( SCALE_GPIO_PIN_TRG, false  );
    for(i = 0; i < WORD_SIZE; i += 4)
    {
        for (j = 0; j < WORDS_PER_BLOCK; j++)
        {
            input_space[ i * WORDS_PER_BLOCK + j] ^= input_space[ (i+1) * WORDS_PER_BLOCK + j]^input_space[ (i+2) * WORDS_PER_BLOCK + j]^input_space[ (i+3) * WORDS_PER_BLOCK + j];
        }
    }
    //mo: change memmove    c|m|c|m output every the other byte
    memmove(outputb,input_space, 16);
}

void aes_ecb(uint8_t* pt_single,uint8_t* key_vector, uint8_t* ct_single)
{
    aesm_ecb_encrypt(ct_single, pt_single, key_vector);

    
}
