
#include <stdint.h>
#include <string.h>
#include <scale/scale.h>
#define BLOCK_SIZE          128
#define KEY_SCHEDULE_SIZE   176
#define WORD_SIZE           32
#define BS_BLOCK_SIZE       (BLOCK_SIZE * WORD_SIZE / 8)  //total # of bytes (32*16)
#define WORDS_PER_BLOCK     (BLOCK_SIZE / WORD_SIZE)  //4
typedef uint32_t    word_t;
#define ONE         1UL
#define MUL_SHIFT   5
#define WFMT        "x"
#define WPAD        "08"
#define __builtin_bswap_wordsize(x) __builtin_bswap32(x)


void bs_transpose(word_t * blocks);
void bs_transpose_rev(word_t * blocks);
void bs_transpose_dst(word_t * transpose, word_t * blocks);

void bs_sbox(word_t U[8]);

void bs_shiftmix(word_t * B);

void bs_addroundkey(word_t * B);
void bs_apply_sbox(word_t * input);

void expand_key(unsigned char *in,uint8_t round);
void bs_expand_key( uint8_t * key);

void bs_cipher(word_t state[BLOCK_SIZE], uint8_t* key, uint8_t* maskb);


