

//Following Dan's README.md on https://github.com/danpage/scale-hw/tree/fa15667bf32cdae6ed65c8f2c26735290ff85429
//For M0: export TARGET="${SCALE_HW}/target/lpc1114fn28"
//	  16 blocks Full Encryption (key expansion/slicing cost included)     	:12MHz <134.67ms
//	  Triggered Time (First Sbox in the first Round)	:12MHz <232.5us
//	  Image Size					:12860
//For M3: export TARGET="${SCALE_HW}/target/lpc1313fbd48"
//Make & Program: sudo  make --no-builtin-rules -f ${TARGET}/build/lib/scale.mk BSP="${TARGET}/build" USB="/dev/ttyUSB0" PROJECT="BS_maskedAES" PROJECT_SOURCES="aes_core.h aes_locl.h aes_rng.h key_schedule.h bs.h Multiplication.s aes_core.c aes_rng.c bs.c BS_maskedAES.c" clean all program
/* UART communication 
 * Recieving 17(or 18) Bytes: 16 bytes AES plaintext + BlockRepeat+ InternalRepeat (if the triggered multiplication is selected) 
 * BlockRepeat: 1-8. This 4-share version can compute 8 blocks' AES encyrption at once. BlockRepeat defines how many blocks are using the
 * 		AES plaintext. If BlockRepeat>1, those bits are all computing the same AES plaintext, yet with different shares. All   
 *              other positions are set to random plaintext and random shares, whose ciphertext will not be returned to UART.
 * 
 * InternalRepeat:0-255. Defines how many times we should repeat the targeted triggered multiplication. As Picoscope has a 
 * rapid-triggering mode, it can usually captured a lot of traces at once. In this case, it would be quite slow to ran through the whole 
 * AES again, so we added an extra procedure to produce multiple traces within one encryption process. If this byte is 0, the 
 * multiplication; otherwise, it will be repeated 10 times this byte. 
 *
 * Returning 16 Bytes: 16 bytes AES ciphertext. There is an option to use the first 4 bytes to return the operand in the target 
 * multiplication, by changing a few lines in "bs.c".s
 */
#include <stdio.h>
#include <stdlib.h>

#include "BS_maskedAES.h"


int main( int argc, char* argv[] ) {

 if( !scale_init( &SCALE_CONF ) ) {
    return -1;
  }
  uint8_t plain[16];
  uint8_t cipher[16];
  uint8_t key[ 16 ] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                      0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
    
  uint8_t k[ 16 ] ;
  //prng initialization
  prng(1);
    while( true ) 
    {

         for( int i = 0; i < 16; i++ ) 
	 {
             	plain[i]=(uint8_t)scale_uart_rd(SCALE_UART_MODE_BLOCKING);
                k[i]=key[i];
         }
         
         aes_ecb(plain,k, cipher);
         
    	 for( int i = 0; i <16; i++ ) 
	 {
                scale_uart_wr(SCALE_UART_MODE_BLOCKING,( (char)cipher[ i ] ));
    	 }
    }


    return 0;
}
