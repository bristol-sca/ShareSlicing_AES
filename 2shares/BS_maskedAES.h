

#include <scale/scale.h>
#include "bs.h"
#include "aes_rng.h"

#define BLOCK_NUM 16   //how many AES run in parallel
#define x BLOCK_NUM*16
#define RANDOM
void aesm_ecb_encrypt(uint8_t * outputb, uint8_t * inputb, uint8_t * m_vector, size_t size, uint8_t * key)
{
    uint8_t * maskb = m_vector;//this one has 1024B randomness
    int i,j;
    word_t input_space[BLOCK_SIZE];//128 bits as 128 words
    uint8_t block_repeat=(uint8_t)scale_uart_rd(SCALE_UART_MODE_BLOCKING);
    memset(input_space,0,BS_BLOCK_SIZE);
    //i=0,2,..,30
    for(i = 0; i < 2*size/16; i += 2)  
    {
       if(i>=block_repeat*2)//Random Blocks
        memmove(input_space + (i * WORDS_PER_BLOCK), prng(0), BLOCK_SIZE/8);
       else//Real Plaintext
        memmove(input_space + (i * WORDS_PER_BLOCK), inputb, BLOCK_SIZE/8);

        memmove(input_space + (i * WORDS_PER_BLOCK + WORDS_PER_BLOCK), maskb, BLOCK_SIZE/8);//16block of mask

        maskb += BLOCK_SIZE/8;
        //inputb += BLOCK_SIZE/8;

        for (j = 0; j < WORDS_PER_BLOCK; j++)
        {
            input_space[ i * WORDS_PER_BLOCK + j] ^= input_space[ i * WORDS_PER_BLOCK + WORDS_PER_BLOCK + j];//first halve become p^m
        }   //  |p+m|m|p+m|m|... p:certain byte of plaintext  
    }
    //Add new randomness
    //assign rng (16 bytes) to mask (512 bytes)  32 loop
    for (i=0; i<32; i++) //32 block=32*16B=512B Randomness
    {
        memmove(m_vector+i*16, prng(0), 16);
    }


    bs_cipher(input_space, key, m_vector);//Core encryption

    for(i = 0; i < WORD_SIZE; i += 2)
    {
        for (j = 0; j < WORDS_PER_BLOCK; j++)
        {
            input_space[ i * WORDS_PER_BLOCK + j] ^= input_space[ i * WORDS_PER_BLOCK + WORDS_PER_BLOCK + j];
        }
    }

    memmove(outputb,input_space, 16);
}

void aes_ecb(uint8_t* pt_single,uint8_t* key_vector, uint8_t* ct_single)
{
    uint8_t m_vector[512];
    int i;
    
    //Add randomness
    //assign rng (16 bytes) to mask (256 bytes)  16 loop
    for (i=0; i<16; i++) //32 block=32*16B=512B Randomness
    {
        memmove(m_vector+i*16, prng(0), 16);
    }


    aesm_ecb_encrypt(ct_single, pt_single, m_vector, x, key_vector);

    
}
