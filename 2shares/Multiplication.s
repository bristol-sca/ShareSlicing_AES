
.syntax unified
.thumb

.global bdfgss_d2_mult_NoTrigger
.func bdfgss_d2_mult_NoTrigger
bdfgss_d2_mult_NoTrigger:
    push {lr}
    push {r4-r7}
    mov     r7, r8
    push    {r7}
    movs    r4, #0
    movs    r5, #0
    movs    r6, #0
    movs    r7, #0
    mov     r8, r7

    //r0=&a, r1=&b, r2=&result
    //------------------------------------------------------------------------
    // Init phase

    // r0 = a, r1 = b
    ldr     R0, [R0]
    ldr     R1, [R1]
    mov     r4, r1    //r4=b

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    //                               ;;
    //     UNROLLED BDFGSS : D=2     ;;
    //                               ;;
    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    // ------------------------------------------------------------------------
    // r3=r
    // x_1 = a AND b
    ands     r4, r0   //r4=a&b 
    // y_1 = x_1 + r
    eors     r4, r3   //r4=a&b+r

    //-2.75us
    // ------------------------------------------------------------------------
    // s = a AND rot(b,i) + rot(a,i) AND b

    // generation of the mask for rotation by 1 stored in R6
    movs     r6, #0x55
    lsls     r5, r6, #8  //r5=0x5500
    eors     r6, r5      //r6=0x5555
    lsls     r5, r6, #16 //r5=0x55550000
    eors     r6, r5      //r6=0x55555555
    //r6=0x55555555
    // rotation of b by 1

    lsrs    r5, r1, #1 //r5= b>>1
    ands    r5, r6     //r5=(b>>1)&0x55555555
    lsrs    r7, r6, #1 //r7=(0x55555555>>1) 
    bics    r1, r7     //r1=bic(b,(0x55555555>>1))
    lsls    r7, r1, #1 //r7=bic(b,(0x55555555>>1))<<1
    eors    r5, r7     //r5=rot(b,1)


    //-2.25us
    //r10=(b>>>1)
    //product + xor
    // x_2 = a AND rot(b,1)
    ands    r5, r0     //r5=a&rot(b,1)

    // y_2 = y_1 + x_1 
    eors    r5, r4 //r5=a&rot(b,1)+a&b+r

    movs    r4, #0
    // rotation of r by 1
    lsrs    r4, r3, #1  //r4= r>>1
    ands    r4, r6      //r4= (r>>1)&0x55555555
    lsrs    r6, #1      //r6= 0x55555555>>1
    bics    r3, r6      //r3= bic(r, 0x55555555>>1)
    lsls    r6,r3, #1      //r6= (bic(r, 0x55555555>>1)<<1)
    eors    r4, r6      //r4=rot(r,1)
    

    // xor of random
    // y_4 = y_3 + rot(r,1)
    eors r5, r4 

    // return s

    str     r5, [r2]

    pop     {r7}
    mov     r8, r7
    movs    r4, #0
    movs    r5, #0
    movs    r6, #0
    movs    r7, #0
    pop {r4-r7}
    pop  {pc}
.endfunc

.global bdfgss_d2_mult
.func bdfgss_d2_mult
bdfgss_d2_mult:
    push {lr}
    push {r4-r7}
    mov     r7, r8
    push    {r7}
    movs    r4, #0
    movs    r5, #0
    movs    r6, #0
    movs    r7, #0
    mov     r8, r7

    //r0=&a, r1=&b, r2=&result
    //------------------------------------------------------------------------
    // Init phase

    // r0 = a, r1 = b
    ldr     R0, [R0]
    ldr     R1, [R1]
    mov     r4, r1    //r4=b

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    //                               ;;
    //     UNROLLED BDFGSS : D=2     ;;
    //                               ;;
    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    // ------------------------------------------------------------------------
    // r3=r
    // x_1 = a AND b
    //ands     r4, r0   //r4=a&b 
    // y_1 = x_1 + r
    //eors     r4, r3   //r4=a&b+r

    //-2.75us
    // ------------------------------------------------------------------------
    // s = a AND rot(b,i) + rot(a,i) AND b

    // generation of the mask for rotation by 1 stored in R6
    movs     r6, #0x55
    lsls     r5, r6, #8  //r5=0x5500
    eors     r6, r5      //r6=0x5555
    lsls     r5, r6, #16 //r5=0x55550000
    eors     r6, r5      //r6=0x55555555
    //r6=0x55555555
    // rotation of b by 1
    mov r8, r8
    lsrs    r5, r1, #1 //r5= b>>1
    mov r8, r8
   // ands    r5, r6     //r5=(b>>1)&0x55555555
   // lsrs    r7, r6, #1 //r7=(0x55555555>>1) 
   // bics    r1, r7     //r1=bic(b,(0x55555555>>1))
   // lsls    r7, r1, #1 //r7=bic(b,(0x55555555>>1))<<1
   // eors    r5, r7     //r5=rot(b,1)


    //-2.25us
    //r10=(b>>>1)
    //product + xor
    // x_2 = a AND rot(b,1)
   // ands    r5, r0     //r5=a&rot(b,1)

    // y_2 = y_1 + x_1 
  //  eors    r5, r4 //r5=a&rot(b,1)+a&b+r

   // movs    r4, #0
    // rotation of r by 1
   // lsrs    r4, r3, #1  //r4= r>>1
   // ands    r4, r6      //r4= (r>>1)&0x55555555
   // lsrs    r6, #1      //r6= 0x55555555>>1
    //bics    r3, r6      //r3= bic(r, 0x55555555>>1)
    //lsls    r6,r3, #1      //r6= (bic(r, 0x55555555>>1)<<1)
    //eors    r4, r6      //r4=rot(r,1)
    

    // xor of random
    // y_4 = y_3 + rot(r,1)
    //eors r5, r4 

    // return s

   // str     r5, [r2]
      mov     r3, r8
      mov     r4, r8
      mov     r5, r8
      mov     r6, r8

  @Start of trigger
  @Trigger address: 0x50013FFC
  movs r4, #80
  lsls r4, r4, #8
  movs r5, #0
  eors r4, r5  //0x5000
  lsls r4, #16 //0x50000000
  movs r5, #63 //0x3f
  lsls r5,r5,#8 //0x3f00
  eors r4,r5    //0x50003f00
  movs r5, #252
  eors r4,r5    //0x50003ffc
  movs r5,#1
  lsls r5, #8
  ldr  r6, [r4, #0]
  eors r5, r6
  str  r5, [r4, #0]
  nop
  nop
  nop   
  nop
  str  r6, [r4, #0]

    pop     {r7}
    mov     r8, r7
    movs    r4, #0
    movs    r5, #0
    movs    r6, #0
    movs    r7, #0
    pop {r4-r7}
    pop  {pc}
.endfunc

.end
