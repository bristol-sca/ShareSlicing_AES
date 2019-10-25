#include <string.h>
#include "bs.h"
#include "key_schedule.h"

#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) ||\
        defined(__amd64__) || defined(__amd32__)|| defined(__amd16__)
#define bs2le(x) (x)
#define bs2be(x) (x)
#elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) ||\
            (defined(__sparc__))
#define bs2le(x) __builtin_bswap_wordsize(x)
#define bs2be(x) __builtin_bswap_wordsize(x)
#else
#error "endianness not supported"
#endif
word_t rands[128];  //rands has 128 words, each word need 32 bit rng or 4 byte. So in total 512 byte rng needed
word_t rk[BLOCK_SIZE];//sliced version of a round key

extern void bdfgss_d2_mult(uint32_t* a,uint32_t* b,uint32_t* result,uint32_t r);
extern void bdfgss_d2_mult_NoTrigger(uint32_t* a,uint32_t* b,uint32_t* result,uint32_t r);
uint8_t bitswap[256] = {
    0x0, 0x2, 0x1, 0x3, 0x8, 0xa, 0x9, 0xb, 0x4, 0x6, 0x5, 0x7, 0xc, 0xe, 0xd, 0xf, 
    0x20, 0x22, 0x21, 0x23, 0x28, 0x2a, 0x29, 0x2b, 0x24, 0x26, 0x25, 0x27, 0x2c, 0x2e, 0x2d, 0x2f, 
    0x10, 0x12, 0x11, 0x13, 0x18, 0x1a, 0x19, 0x1b, 0x14, 0x16, 0x15, 0x17, 0x1c, 0x1e, 0x1d, 0x1f, 
    0x30, 0x32, 0x31, 0x33, 0x38, 0x3a, 0x39, 0x3b, 0x34, 0x36, 0x35, 0x37, 0x3c, 0x3e, 0x3d, 0x3f, 
    0x80, 0x82, 0x81, 0x83, 0x88, 0x8a, 0x89, 0x8b, 0x84, 0x86, 0x85, 0x87, 0x8c, 0x8e, 0x8d, 0x8f, 
    0xa0, 0xa2, 0xa1, 0xa3, 0xa8, 0xaa, 0xa9, 0xab, 0xa4, 0xa6, 0xa5, 0xa7, 0xac, 0xae, 0xad, 0xaf, 
    0x90, 0x92, 0x91, 0x93, 0x98, 0x9a, 0x99, 0x9b, 0x94, 0x96, 0x95, 0x97, 0x9c, 0x9e, 0x9d, 0x9f, 
    0xb0, 0xb2, 0xb1, 0xb3, 0xb8, 0xba, 0xb9, 0xbb, 0xb4, 0xb6, 0xb5, 0xb7, 0xbc, 0xbe, 0xbd, 0xbf, 
    0x40, 0x42, 0x41, 0x43, 0x48, 0x4a, 0x49, 0x4b, 0x44, 0x46, 0x45, 0x47, 0x4c, 0x4e, 0x4d, 0x4f, 
    0x60, 0x62, 0x61, 0x63, 0x68, 0x6a, 0x69, 0x6b, 0x64, 0x66, 0x65, 0x67, 0x6c, 0x6e, 0x6d, 0x6f, 
    0x50, 0x52, 0x51, 0x53, 0x58, 0x5a, 0x59, 0x5b, 0x54, 0x56, 0x55, 0x57, 0x5c, 0x5e, 0x5d, 0x5f, 
    0x70, 0x72, 0x71, 0x73, 0x78, 0x7a, 0x79, 0x7b, 0x74, 0x76, 0x75, 0x77, 0x7c, 0x7e, 0x7d, 0x7f, 
    0xc0, 0xc2, 0xc1, 0xc3, 0xc8, 0xca, 0xc9, 0xcb, 0xc4, 0xc6, 0xc5, 0xc7, 0xcc, 0xce, 0xcd, 0xcf, 
    0xe0, 0xe2, 0xe1, 0xe3, 0xe8, 0xea, 0xe9, 0xeb, 0xe4, 0xe6, 0xe5, 0xe7, 0xec, 0xee, 0xed, 0xef, 
    0xd0, 0xd2, 0xd1, 0xd3, 0xd8, 0xda, 0xd9, 0xdb, 0xd4, 0xd6, 0xd5, 0xd7, 0xdc, 0xde, 0xdd, 0xdf, 
    0xf0, 0xf2, 0xf1, 0xf3, 0xf8, 0xfa, 0xf9, 0xfb, 0xf4, 0xf6, 0xf5, 0xf7, 0xfc, 0xfe, 0xfd, 0xff
};


#define bs_applymask(x,y) bs_addroundkey(x,y)


void bs_addroundkey(word_t * B)
{
    int i;
    for (i = 0; i < BLOCK_SIZE; i++)
        B[i] ^= rk[i];
}

void bs_apply_sbox(word_t * input)
{
    int i;
   
    for(i=0; i < BLOCK_SIZE; i+=8)//8-bit of all 32 blocks (16 blocks of two-shares)
    {
        bs_sbox(input+i);
          
    }
}

/*July 2011*/
/*Straight-line program for AES s box*/

/*Input is U[0], U[1],...,U[7]*/
/*Output is S[0], S[1],...,S[7]*/
// http://cs-www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html


volatile int rand_indx = 0;

//Secure AND without Trigger
word_t __attribute__ ((noinline)) SAND(word_t p, word_t q)
{

    word_t r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    word_t z=0;
    bdfgss_d2_mult_NoTrigger(&p,&q,&z,r);
    return z;
}
//Secure AND with Trigger
//Forced refresh with new randomness; repeat several times according to the UART input
//To avoid any non-expected leakage, everything after the shift has been commented out;
//If you need the full multiplication, uncomment the instructions in "Multiplication.S" or
//Use the non-triggered version will give the correct result.
word_t __attribute__ ((noinline)) SAND_Trigger(word_t p, word_t q)
{

    /**********************************
     *	Forced refreshing all operands
     *********************************/
    memmove(rands, prng(0), 16);
    rand_indx=0;
    word_t r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    word_t z=0;
    //refresh q first
    word_t r1=r&0xaaaaaaaa;
    r1=r1>>1;
    r1=((r&0x55555555)<<1)^r1;
    q=q^r^r1;
    //refresh p 
    r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    r1=r&0xaaaaaaaa;
    r1=r1>>1;
    r1=((r&0x55555555)<<1)^r1;
    p=p^r^r1;
    r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;

    /**********************************
     *	Read one byte $t$ from the UART
     *  Repeat the multication for $10t$ times
     *********************************/
    uint8_t internal_repeat=(uint8_t)scale_uart_rd(SCALE_UART_MODE_BLOCKING);
    int repeat=10*internal_repeat;
    if(repeat==0)
       repeat=1;

    for(int i=0;i<repeat;i++)
   {
    /**************************************************************************************************************
    *  Refreshing the operands
    *  Whether refresh within the loop depends on the following processing:
    *  1) if all traces are averaged first, then use the average trace in TVLA, it would be better not the refresh
    *  2) if all traces are taken into TVLA, it would be better to refresh the operand.
    **************************************************************************************************************/
    memmove(rands, prng(0), 16);
    rand_indx=0;
    word_t r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    word_t z=0;
    //refresh q first
    word_t r1=r&0xaaaaaaaa;
    r1=r1>>1;
    r1=((r&0x55555555)<<1)^r1;
    q=q^r^r1;
    //refresh p 
    r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    r1=r&0xaaaaaaaa;
    r1=r1>>1;
    r1=((r&0x55555555)<<1)^r1;
    p=p^r^r1;
    r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    /**************************************************************************************************************
     *  The following 3 lines set 0 to the non-target bits in the operands. 
     *  As the full scheme is originally implemeneted for performance, all 32 bits will be ultilized anyway
     *  To test the case when all non-target bits are 0, it is much easier to change it here
     **************************************************************************************************************/
     //p=p&0xff;
     //q=q&0xff;
     //r=r&0xff;
     /**********************************
      *	Target multiplication 
     *********************************/
     bdfgss_d2_mult(&p,&q,&z,r);
   }

    return z;
}
void bs_sbox(word_t U[8])//Masked Sbox
{

    word_t
        T1,T2,T3,T4,T5,T6,T7,T8,
        T9,T10,T11,T12,T13,T14,T15,T16,
        T17,T18,T19,T20,T21,T22,T23,T24,
        T25, T26, T27;


    word_t
        M1,M2,M3,M4,M5,M6,M7,M8,
        M9,M10,M11,M12,M13,M14,M15,
        M16,M17,M18,M19,M20,M21,M22,
        M23,M24,M25,M26,M27,M28,M29,
        M30,M31,M32,M33,M34,M35,M36,
        M37,M38,M39,M40,M41,M42,M43,
        M44,M45,M46,M47,M48,M49,M50,
        M51,M52,M53,M54,M55,M56,M57,
        M58,M59,M60,M61,M62,M63;

    word_t
        L0,L1,L2,L3,L4,L5,L6,L7,L8,
        L9,L10,L11,L12,L13,L14,
        L15,L16,L17,L18,L19,L20,
        L21,L22,L23,L24,L25,L26,
        L27,L28,L29;



    T1 = U[7] ^ U[4];
    T2 = U[7] ^ U[2];
    T3 = U[7] ^ U[1];
    T4 = U[4] ^ U[2];
    T5 = U[3] ^ U[1];
    T6 = T1 ^ T5;
    T7 = U[6] ^ U[5];
    T8 = U[0] ^ T6;
    T9 = U[0] ^ T7;
    T10 = T6 ^ T7;
    T11 = U[6] ^ U[2];
    T12 = U[5] ^ U[2];
    T13 = T3 ^ T4;
    T14 = T6 ^ T11;
    T15 = T5 ^ T11;
    T16 = T5 ^ T12;
    T17 = T9 ^ T16;
    T18 = U[4] ^ U[0];
    T19 = T7 ^ T18;
    T20 = T1 ^ T19;
    T21 = U[1] ^ U[0];
    T22 = T7 ^ T21;
    T23 = T2 ^ T22;
    T24 = T2 ^ T10;
    T25 = T20 ^ T17;
    T26 = T3 ^ T16;
    T27 = T1 ^ T12;

    /*M1 = T13 & T6;*/
    M1 = SAND(T13,T6);//Masked AND2

    /*M2 = T23 & T8;*/
    M2 = SAND(T23,T8);
     
    M3 = T14 ^ M1;   //M0:12MHz <6.85us 

    //M4 = T19 & U[0];
    M4 = SAND(T19,U[0]);

    M5 = M4 ^ M1;

    //M6 = T3 & T16;
    M6 = SAND(T3,T16);
    //M7 = T22 & T9;
    M7 = SAND(T22,T9);
    
    M8 = T26 ^ M6;

    //M9 = T20 & T17;
    M9 = SAND(T20,T17);

    M10 = M9 ^ M6;

    //M11 = T1 & T15;
    M11 = SAND(T1,T15);
    //M12 = T4 & T27;
    M12 = SAND(T4,T27);

    M13 = M12 ^ M11;

    //M14 = T2 & T10;
    M14 = SAND(T2,T10);

    M15 = M14 ^ M11;
    M16 = M3 ^ M2;
    M17 = M5 ^ T24;
    M18 = M8 ^ M7;
    M19 = M10 ^ M15;
    M20 = M16 ^ M13;
    M21 = M17 ^ M15;
    M22 = M18 ^ M13;
    M23 = M19 ^ T25;
    M24 = M22 ^ M23;

    //M25 = M22 & M20;
    M25 = SAND(M22,M20);
  
    M26 = M21 ^ M25;
    M27 = M20 ^ M21;
    M28 = M23 ^ M25;

    //M29 = M28 & M27;
    M29 = SAND(M28,M27);
    //M30 = M26 & M24;
    M30 = SAND(M26,M24);
    //M31 = M20 & M23;
    M31 = SAND(M20,M23);
    //M32 = M27 & M31;/
    M32 = SAND(M27,M31);

    M33 = M27 ^ M25;

    //M34 = M21 & M22;
    M34 = SAND(M21,M22);
    //M35 = M24 & M34;
    M35 = SAND(M24,M34);

    M36 = M24 ^ M25;
    M37 = M21 ^ M29;
    M38 = M32 ^ M33;
    M39 = M23 ^ M30;
    M40 = M35 ^ M36;
    M41 = M38 ^ M40;
    M42 = M37 ^ M39;
    M43 = M37 ^ M38;
    M44 = M39 ^ M40;
    M45 = M42 ^ M41;

    //M46 = M44 & T6;
    M46 = SAND(M44,T6);
    //M47 = M40 & T8;
    M47 = SAND(M40,T8);
    //M48 = M39 & U[0];
    M48 = SAND(M39,U[0]);
    //M49 = M43 & T16;
    M49 = SAND(M43,T16);
    //M50 = M38 & T9;
    M50 = SAND(M38,T9);
    //M51 = M37 & T17;
    M51 = SAND(M37,T17);
    //M52 = M42 & T15;
    M52 = SAND(M42,T15);
    //M53 = M45 & T27;
    M53 = SAND(M45,T27);
    //M54 = M41 & T10;
    M54 = SAND(M41,T10);
    //M55 = M44 & T13;
    M55 = SAND(M44,T13);
    //M56 = M40 & T23;
    M56 = SAND(M40,T23);
    //M57 = M39 & T19;
    M57 = SAND(M39,T19);
    //M58 = M43 & T3;
    M58 = SAND(M43,T3);
    //M59 = M38 & T22;
    M59 = SAND(M38,T22);
    //M60 = M37 & T20;
    M60 = SAND(M37,T20);
    //M61 = M42 & T1;
    M61 = SAND(M42,T1);
    //M62 = M45 & T4;
    M62 = SAND(M45,T4);
    //M63 = M41 & T2;
    M63 = SAND(M41,T2);

    L0 = M61 ^ M62;
    L1 = M50 ^ M56;
    L2 = M46 ^ M48;
    L3 = M47 ^ M55;
    L4 = M54 ^ M58;
    L5 = M49 ^ M61;
    L6 = M62 ^ L5;
    L7 = M46 ^ L3;
    L8 = M51 ^ M59;
    L9 = M52 ^ M53;
    L10 = M53 ^ L4;
    L11 = M60 ^ L2;
    L12 = M48 ^ M51;
    L13 = M50 ^ L0;
    L14 = M52 ^ M61;
    L15 = M55 ^ L1;
    L16 = M56 ^ L0;
    L17 = M57 ^ L1;
    L18 = M58 ^ L8;
    L19 = M63 ^ L4;
    L20 = L0 ^ L1;
    L21 = L1 ^ L7;
    L22 = L3 ^ L12;
    L23 = L18 ^ L2;
    L24 = L15 ^ L9;
    L25 = L6 ^ L10;
    L26 = L7 ^ L9;
    L27 = L8 ^ L10;
    L28 = L11 ^ L14;
    L29 = L11 ^ L17;
    U[7] = L6 ^ L24;
    //U[6] = ~(L16 ^ L26);
    U[6] = 0x55555555 ^ (L16 ^ L26);
    //U[5] = ~(L19 ^ L28);
    U[5] = 0x55555555 ^ (L19 ^ L28);
    U[4] = L6 ^ L21;
    U[3] = L20 ^ L22;
    U[2] = L25 ^ L29;
    //U[1] = ~(L13 ^ L27);
    U[1] = 0x55555555 ^ (L13 ^ L27);
    //U[0] = ~(L6 ^ L23);
    U[0] = 0x55555555 ^ (L6 ^ L23);

}

void bs_transpose(word_t * blocks)
{
    word_t transpose[BLOCK_SIZE];
    memset(transpose, 0, sizeof(transpose));
    bs_transpose_dst(transpose,blocks);
    memmove(blocks,transpose,sizeof(transpose));
}

void bs_transpose_dst(word_t * transpose, word_t * blocks)//transpose: new array
{
    int i,k;
    word_t w;
    for(k=0; k < WORD_SIZE; k++)//32 bit in the transposed word; a.k.a the block index in the original block array
    {
        int bitpos = ONE << k;
        for (i=0; i < WORDS_PER_BLOCK; i++)//word index in the original blocks
        {
            w = bs2le(blocks[k * WORDS_PER_BLOCK + i]);//Get the original word, to Little endianness
            int offset = i << MUL_SHIFT;

            int j;
            for(j=0; j < WORD_SIZE; j++)
            {
                // TODO make const time
                transpose[offset + j] |= (w & (ONE << j)) ? bitpos : 0;
            }

                // constant time:
                //transpose[(i<<MUL_SHIFT)+ j] |= (((int64_t)((w & (ONE << j)) << (WORD_SIZE-1-j)))>>(WORD_SIZE-1)) & (ONE<<k);
        }
    }
}

void bs_transpose_rev(word_t * blocks)
{
    int i,k;
    word_t w;
    word_t transpose[BLOCK_SIZE];
    memset(transpose, 0, sizeof(transpose));
    for(k=0; k < BLOCK_SIZE; k++)//For all 128 bits
    {
        w = blocks[k];//bit k
        word_t bitpos = bs2be(ONE << (k % WORD_SIZE));//position in one word
        word_t offset = k / WORD_SIZE;//word position in 4 word array

        int j;
        for(j=0; j < WORD_SIZE; j++)
        {
            word_t bit = (w & (ONE << j)) ? (ONE << (k % WORD_SIZE)) : 0;
            transpose[j * WORDS_PER_BLOCK + (offset)] |= bit;
        }

    }
    memmove(blocks,transpose,sizeof(transpose));
}


#define R0          0
#define R1          8
#define R2          16
#define R3          24

#define B0          0
#define B1          32
#define B2          64
#define B3          96

#define R0_shift        (BLOCK_SIZE/4)*0
#define R1_shift        (BLOCK_SIZE/4)*1
#define R2_shift        (BLOCK_SIZE/4)*2
#define R3_shift        (BLOCK_SIZE/4)*3
#define B_MOD           (BLOCK_SIZE)


#define A0  0
#define A1  8
#define A2  16
#define A3  24
void bs_shiftrows(word_t * B)
{
    word_t Bp_space[BLOCK_SIZE];
    word_t * Bp = Bp_space;
    word_t * Br0 = B + 0;
    word_t * Br1 = B + 32;
    word_t * Br2 = B + 64;
    word_t * Br3 = B + 96;
    uint8_t offsetr0 = 0;
    uint8_t offsetr1 = 32;
    uint8_t offsetr2 = 64;
    uint8_t offsetr3 = 96;


    int i;
    for(i=0; i<4; i++)
    {
        Bp[B0 + 0] = Br0[0];
        Bp[B0 + 1] = Br0[1];
        Bp[B0 + 2] = Br0[2];
        Bp[B0 + 3] = Br0[3];
        Bp[B0 + 4] = Br0[4];
        Bp[B0 + 5] = Br0[5];
        Bp[B0 + 6] = Br0[6];
        Bp[B0 + 7] = Br0[7];
        Bp[B1 + 0] = Br1[0];
        Bp[B1 + 1] = Br1[1];
        Bp[B1 + 2] = Br1[2];
        Bp[B1 + 3] = Br1[3];
        Bp[B1 + 4] = Br1[4];
        Bp[B1 + 5] = Br1[5];
        Bp[B1 + 6] = Br1[6];
        Bp[B1 + 7] = Br1[7];
        Bp[B2 + 0] = Br2[0];
        Bp[B2 + 1] = Br2[1];
        Bp[B2 + 2] = Br2[2];
        Bp[B2 + 3] = Br2[3];
        Bp[B2 + 4] = Br2[4];
        Bp[B2 + 5] = Br2[5];
        Bp[B2 + 6] = Br2[6];
        Bp[B2 + 7] = Br2[7];
        Bp[B3 + 0] = Br3[0];
        Bp[B3 + 1] = Br3[1];
        Bp[B3 + 2] = Br3[2];
        Bp[B3 + 3] = Br3[3];
        Bp[B3 + 4] = Br3[4];
        Bp[B3 + 5] = Br3[5];
        Bp[B3 + 6] = Br3[6];
        Bp[B3 + 7] = Br3[7];

        offsetr0 = (offsetr0 + BLOCK_SIZE/16 + BLOCK_SIZE/4) & 0x7f;
        offsetr1 = (offsetr1 + BLOCK_SIZE/16 + BLOCK_SIZE/4) & 0x7f;
        offsetr2 = (offsetr2 + BLOCK_SIZE/16 + BLOCK_SIZE/4) & 0x7f;
        offsetr3 = (offsetr3 + BLOCK_SIZE/16 + BLOCK_SIZE/4) & 0x7f;

        Br0 = B + offsetr0;
        Br1 = B + offsetr1;
        Br2 = B + offsetr2;
        Br3 = B + offsetr3;

        Bp += 8;
    }
    memmove(B,Bp_space,sizeof(Bp_space));
}


// Does shift rows and mix columns in same step
void bs_shiftmix(word_t * B)
{
    word_t Bp_space[BLOCK_SIZE];
    word_t * Bp = Bp_space;

    word_t * Br0 = B + 0;
    word_t * Br1 = B + 32;
    word_t * Br2 = B + 64;
    word_t * Br3 = B + 96;

    uint8_t offsetr0 = 0;
    uint8_t offsetr1 = 32;
    uint8_t offsetr2 = 64;
    uint8_t offsetr3 = 96;

        Br0 = B + offsetr0;//row 0
        Br1 = B + offsetr1;//row 1
        Br2 = B + offsetr2;//row 2
        Br3 = B + offsetr3;//row 3


    int i;
    for (i = 0; i < 4; i++)
    {
        // B0
        //            2*A0        2*A1              A1           A2           A3
        word_t of =Br0[R0+7]^ Br1[R1+7];//hsb of (B00+B11)
        Bp[A0+0] =                         Br1[R1+0] ^ Br2[R2+0] ^ Br3[R3+0] ^ of;//bit 0: 1
        Bp[A0+1] = Br0[R0+0] ^ Br1[R1+0] ^ Br1[R1+1] ^ Br2[R2+1] ^ Br3[R3+1] ^ of;//bit 1: 1
        Bp[A0+2] = Br0[R0+1] ^ Br1[R1+1] ^ Br1[R1+2] ^ Br2[R2+2] ^ Br3[R3+2];     //bit 2: 0
        Bp[A0+3] = Br0[R0+2] ^ Br1[R1+2] ^ Br1[R1+3] ^ Br2[R2+3] ^ Br3[R3+3] ^ of;//bit 3: 1
        Bp[A0+4] = Br0[R0+3] ^ Br1[R1+3] ^ Br1[R1+4] ^ Br2[R2+4] ^ Br3[R3+4] ^ of;//bit 4: 1
        Bp[A0+5] = Br0[R0+4] ^ Br1[R1+4] ^ Br1[R1+5] ^ Br2[R2+5] ^ Br3[R3+5];     //bit 5: 0
        Bp[A0+6] = Br0[R0+5] ^ Br1[R1+5] ^ Br1[R1+6] ^ Br2[R2+6] ^ Br3[R3+6];     //bit 6: 0
        Bp[A0+7] = Br0[R0+6] ^ Br1[R1+6] ^ Br1[R1+7] ^ Br2[R2+7] ^ Br3[R3+7];     //bit 7: 0
        //Field=x^8+x^4+x^3+x+1

        //            A0            2*A1        2*A2        A2       A3
        of = Br1[R1+7] ^ Br2[R2+7];
        Bp[A1+0] = Br0[R0+0]                         ^ Br2[R2+0] ^ Br3[R3+0] ^ of;
        Bp[A1+1] = Br0[R0+1] ^ Br1[R1+0] ^ Br2[R2+0] ^ Br2[R2+1] ^ Br3[R3+1] ^ of;
        Bp[A1+2] = Br0[R0+2] ^ Br1[R1+1] ^ Br2[R2+1] ^ Br2[R2+2] ^ Br3[R3+2];
        Bp[A1+3] = Br0[R0+3] ^ Br1[R1+2] ^ Br2[R2+2] ^ Br2[R2+3] ^ Br3[R3+3] ^ of;
        Bp[A1+4] = Br0[R0+4] ^ Br1[R1+3] ^ Br2[R2+3] ^ Br2[R2+4] ^ Br3[R3+4] ^ of;
        Bp[A1+5] = Br0[R0+5] ^ Br1[R1+4] ^ Br2[R2+4] ^ Br2[R2+5] ^ Br3[R3+5];
        Bp[A1+6] = Br0[R0+6] ^ Br1[R1+5] ^ Br2[R2+5] ^ Br2[R2+6] ^ Br3[R3+6];
        Bp[A1+7] = Br0[R0+7] ^ Br1[R1+6] ^ Br2[R2+6] ^ Br2[R2+7] ^ Br3[R3+7];

        //            A0             A1      2*A2        2*A3         A3
        of = Br2[R2+7] ^ Br3[R3+7];
        Bp[A2+0] = Br0[R0+0] ^ Br1[R1+0]                         ^ Br3[R3+0] ^ of;
        Bp[A2+1] = Br0[R0+1] ^ Br1[R1+1] ^ Br2[R2+0] ^ Br3[R3+0] ^ Br3[R3+1] ^ of;
        Bp[A2+2] = Br0[R0+2] ^ Br1[R1+2] ^ Br2[R2+1] ^ Br3[R3+1] ^ Br3[R3+2];
        Bp[A2+3] = Br0[R0+3] ^ Br1[R1+3] ^ Br2[R2+2] ^ Br3[R3+2] ^ Br3[R3+3] ^ of;
        Bp[A2+4] = Br0[R0+4] ^ Br1[R1+4] ^ Br2[R2+3] ^ Br3[R3+3] ^ Br3[R3+4] ^ of;
        Bp[A2+5] = Br0[R0+5] ^ Br1[R1+5] ^ Br2[R2+4] ^ Br3[R3+4] ^ Br3[R3+5];
        Bp[A2+6] = Br0[R0+6] ^ Br1[R1+6] ^ Br2[R2+5] ^ Br3[R3+5] ^ Br3[R3+6];
        Bp[A2+7] = Br0[R0+7] ^ Br1[R1+7] ^ Br2[R2+6] ^ Br3[R3+6] ^ Br3[R3+7];

        //             A0          2*A0           A1       A2      2*A3
        of = Br0[R0+7] ^ Br3[R3+7];
        Bp[A3+0] = Br0[R0+0] ^             Br1[R1+0] ^ Br2[R2+0]             ^ of;
        Bp[A3+1] = Br0[R0+1] ^ Br0[R0+0] ^ Br1[R1+1] ^ Br2[R2+1] ^ Br3[R3+0] ^ of;
        Bp[A3+2] = Br0[R0+2] ^ Br0[R0+1] ^ Br1[R1+2] ^ Br2[R2+2] ^ Br3[R3+1];
        Bp[A3+3] = Br0[R0+3] ^ Br0[R0+2] ^ Br1[R1+3] ^ Br2[R2+3] ^ Br3[R3+2] ^ of;
        Bp[A3+4] = Br0[R0+4] ^ Br0[R0+3] ^ Br1[R1+4] ^ Br2[R2+4] ^ Br3[R3+3] ^ of;
        Bp[A3+5] = Br0[R0+5] ^ Br0[R0+4] ^ Br1[R1+5] ^ Br2[R2+5] ^ Br3[R3+4];
        Bp[A3+6] = Br0[R0+6] ^ Br0[R0+5] ^ Br1[R1+6] ^ Br2[R2+6] ^ Br3[R3+5];
        Bp[A3+7] = Br0[R0+7] ^ Br0[R0+6] ^ Br1[R1+7] ^ Br2[R2+7] ^ Br3[R3+6];

        Bp += BLOCK_SIZE/4;

        offsetr0 = (offsetr0 + BLOCK_SIZE/4) & 0x7f;
        offsetr1 = (offsetr1 + BLOCK_SIZE/4) & 0x7f;
        offsetr2 = (offsetr2 + BLOCK_SIZE/4) & 0x7f;
        offsetr3 = (offsetr3 + BLOCK_SIZE/4) & 0x7f;

        Br0 = B + offsetr0;
        Br1 = B + offsetr1;
        Br2 = B + offsetr2;
        Br3 = B + offsetr3;
    }

    memmove(B,Bp_space,sizeof(Bp_space));
}


void bs_expand_key_round(uint8_t * key)
{
    int k;
    for (k = 0; k < WORD_SIZE; k += 2)//key=0,2,4,...,30
   {
     memmove(rk + k * WORDS_PER_BLOCK, key, BLOCK_SIZE / 8);//first share of key set to round key (block 1)

     memset(rk + (k+1) * WORDS_PER_BLOCK, 0, BLOCK_SIZE / 8);//the second share of key set to 0 (block 2)

    }


    bs_transpose(rk);//transfer to bitsliced version
       
    
}

void bs_cipher(word_t* state, uint8_t* key, uint8_t* maskb)
{

	 uint8_t tmp1,tmp2,tmp3,tmp4;
	 uint32_t tmp;
	 word_t rng;
	 int index;
	 int i,j;
	 int round;

    //add the rng for sand
    memset(rands,0,128);
    //it seems like from byte 256 to byte 511, the values in maskb are never used???
    for (i=0; i<512; i+=4)//altogether 512 Bytes, transfer to 128 32-bit random masks
    {
        tmp1 = *(maskb+i);
        tmp2 = *(maskb+i+1);
        tmp3 = *(maskb+i+2);
        tmp4 = *(maskb+i+3);
        tmp = ((uint32_t)tmp4 << 24) |((uint32_t)tmp3 << 16) |((uint32_t)tmp2 << 8) | tmp1;//32 bit randomness

        index = i/4;
        rands[index] = tmp;//store it to rands
    }
    
    
    
    bs_transpose(state);//transpose the input state to the sliced form (p^m|m|p^m|m.....)
                        //M0:12MHz 7.95ms
    bs_expand_key_round(key);//M0:12MHz 8.2ms

    bs_addroundkey(state);//addroundkey 0
			  //M0:12MHz 180us
    /********************************************************************************************************
     *	The following code is the original 10 rounds of encryption: for speed, one can simply call one "bs_sbox(state)"
     *     to compute the first Sbox and omit everything afterwise. This trick will significantly speed-up the 
     *     acquisition process.  
     *******************************************************************************************************/

    for (round = 1; round < 10; round++)
    {
        
        bs_apply_sbox(state);//masked Sbox
			     //M0:12MHz 4.63ms
      
       

        bs_shiftmix(state);//M0:12MHz 350us 

	expand_key(key,round);//M0:12MHz 64us 
 

       bs_expand_key_round(key);//M0:12MHz 8.2ms

        bs_addroundkey(state);//addroundkey[round]
			      //M0:12MHz 180us
    }

    bs_apply_sbox(state);//M0:12MHz 4.63ms
  
    bs_shiftrows(state);//M0:12MHz 160us 

    expand_key(key,10);//M0:12MHz 64us 
    bs_expand_key_round(key);//M0:12MHz 8.2ms
    bs_addroundkey(state);//M0:12MHz 180us

    bs_transpose_rev(state);//M0:12MHz 8.8ms 
}


