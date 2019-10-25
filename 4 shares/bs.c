#include <string.h>
#include "bs.h"
#include "key_schedule.h"
#include <scale/scale.h>
#include "aes_rng.h"
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
word_t rands[128];  //rands has 256 words, each word need 32 bit rng or 4 byte. So in total 1024 byte rng needed
word_t rk[BLOCK_SIZE];//sliced version of a round key

word_t M34_out;//debug
extern void bdfgss_d4_mult_Left_NoTrigger(uint32_t* a,uint32_t* b,uint32_t* result,uint32_t r);

extern uint32_t bdfgss_d4_mult_Right_Trigger(uint32_t a,uint32_t b,uint32_t r);

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
    //refresh q first
    word_t r1=r&0xeeeeeeee;
    r1=r1>>1;
    r1=((r&0x111111111)<<3)^r1;
    q=q^r^r1;
    //refresh p
    r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    r1=r&0xeeeeeeee;
    r1=r1>>1;
    r1=((r&0x111111111)<<3)^r1;
    p=p^r^r1;
    //load new random
    r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    word_t z=0;
 
    //bdfgss_d2_mult_NoTrigger(&p,&q,&z,r);
    bdfgss_d4_mult_Left_NoTrigger(&p,&q,&z,r);
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
    for (int j=0; j<32; j++) //64*16/4=256 words
       memmove(rands+j*16, prng(0), 16);
    rand_indx=0;
    word_t z=0;
    word_t r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    //refresh q first
    word_t r1=r&0xeeeeeeee;
    r1=r1>>1;
    r1=((r&0x111111111)<<3)^r1;
    q=q^r^r1;
    //refresh p
    r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    r1=r&0xeeeeeeee;
    r1=r1>>1;
    r1=((r&0x111111111)<<3)^r1;
    p=p^r^r1;
    //load new random
    r=rands[((rand_indx) & 0x7f)];
    rand_indx=(rand_indx+1)&0x7f;
    z=0; 
  
    /**********************************
     *	Read one byte $t$ from the UART
     *  Repeat the multication for $10t$ times
     *********************************/
    uint8_t repeat=(uint8_t)scale_uart_rd(SCALE_UART_MODE_BLOCKING);
    int repeatt=repeat*10;
    if(repeatt==0)
      repeatt=1;
    for(int i=0;i<repeatt;i++)
    {
     	/**************************************************************************************************************
    	 *  Refreshing the operands
	 *  Whether refresh within the loop depends on the following processing:
     	 *  1) if all traces are averaged first, then use the average trace in TVLA, it would be better not the refresh
         *  2) if all traces are taken into TVLA, it would be better to refresh the operand.
    	 **************************************************************************************************************/
	  memmove(rands, prng(0), 16);
          rand_indx=0;
          z=0;
          r=rands[((rand_indx) & 0x7f)];
    	  rand_indx=(rand_indx+1)&0x7f;
    	  //refresh q first
    	  r1=r&0xeeeeeeee;
    	  r1=r1>>1;
    	  r1=((r&0x111111111)<<3)^r1;
    	  q=q^r^r1;
          //refresh p
    	  r=rands[((rand_indx) & 0x7f)];
    	  rand_indx=(rand_indx+1)&0x7f;
          r1=r&0xeeeeeeee;
    	  r1=r1>>1;
    	  r1=((r&0x111111111)<<3)^r1;
    	  p=p^r^r1;
    	  //load new random
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
           //z=bdfgss_d4_mult_Right_Trigger(p,q,r);
           bdfgss_d4_mult_Left_NoTrigger(&p,&q,&z,r);
    }

      	  /**************************************************************************************************
           *	This line helps return $q$ to the UART, which serves as a confirmation of the unshared value
           *************************************************************************************************/
           M34_out=q;

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
    //M35 = SAND_Trigger(M24,M34);
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
    U[6] = 0x11111111 ^ (L16 ^ L26);
    //U[5] = ~(L19 ^ L28);
    U[5] = 0x11111111 ^ (L19 ^ L28);
    U[4] = L6 ^ L21;
    U[3] = L20 ^ L22;
    U[2] = L25 ^ L29;
    //U[1] = ~(L13 ^ L27);
    U[1] = 0x11111111 ^ (L13 ^ L27);
    //U[0] = ~(L6 ^ L23);
    U[0] = 0x11111111 ^ (L6 ^ L23);

}

void bs_transpose(word_t * blocks)
{
    word_t transpose[BLOCK_SIZE];
    memset(transpose, 0, sizeof(transpose));
    bs_transpose_dst(transpose,blocks);
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



void bs_expand_key_round(uint8_t * key)
{
    int k;
    for (k = 0; k < WORD_SIZE; k += 4)//
   {
     memmove(rk + k * WORDS_PER_BLOCK, key, BLOCK_SIZE / 8);//first share of key set to round key (block 1)

     memset(rk + (k+1) * WORDS_PER_BLOCK, 0, BLOCK_SIZE / 8);//the second share of key set to 0 (block 2)
     memset(rk + (k+2) * WORDS_PER_BLOCK, 0, BLOCK_SIZE / 8);//the third share of key set to 0 (block 3)
     memset(rk + (k+3) * WORDS_PER_BLOCK, 0, BLOCK_SIZE / 8);//the last share of key set to 0 (block 4)
    }


    bs_transpose(rk);//transfer to bitsliced version
       
    
}

void bs_cipher(word_t* state, uint8_t* key)
{


	 int i,j;
	 int round;

    	 for (i=0; i<32; i++) //64*16/4=256 words
             memmove(rands+i*16, prng(0), 16);

         rand_indx=0;

      	 /********************************************************************************************************
          *	The following code is the original 10 rounds of encryption: for speed, one can simply call one "bs_sbox(state)"
          *     to compute the first Sbox and omit everything afterwise. This trick will significantly speed-up the 
          *     acquisition process.  
          *******************************************************************************************************/
    	 bs_transpose(state);//transpose the input state to the sliced form (p^m|m|p^m|m.....)
                        //M0:12MHz 7.95ms
    	 bs_expand_key_round(key);//M0:12MHz 8.2ms

    	 bs_addroundkey(state);//addroundkey 0
			  //M0:12MHz 180us
        

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

    /**************************************************************************************************
     *	This line helps return $q$ to the UART, which serves as a confirmation of the unshared value
     *************************************************************************************************/
    //state[0]=M34_out;
    //state[4]=0;
    //state[8]=0;
    //state[12]=0;
}


