
.syntax unified
.thumb

.global bdfgss_d4_mult_Left_NoTrigger
.func bdfgss_d4_mult_Left_NoTrigger
bdfgss_d4_mult_Left_NoTrigger:
    push {lr}
    push {r4-r7}
    mov  r4, r9
    mov  r5, r10
    mov  r6, r8
    push {r4-r6}

    movs    r4, #0
    movs    r5, #0
    movs    r6, #0
    movs    r7, #0
    mov     r8, r4
    mov     r9, r4
    mov     r10,r4

    //r0=&a, r1=&b, r2=&result, r3=r
    //------------------------------------------------------------------------
    // First Computation
    // r0 = a, r1 = b
    ldr     R0, [R0]
    ldr     R1, [R1]
    // y_1 = x_1 + r
    mov      r4, r0
    ands     r4, r1
    eors     r4, r3//r4=y1
    // ------------------------------------------------------------------------

    //------------------------------------------------------------------------
    // Inner Loop
    // Generate Mask 0xeeeeeeee
    movs     r5, #0xee
    lsls     r6, r5,#8
    eors     r5, r6    //r5=0xeeee
    lsls     r6, r5,#16//r6=0xeeee0000
    eors     r5, r6    //r5=0xeeeeeeee

    //rotation of b by 1
    lsls     r6, r1, #1//r6=r1<<1
    ands     r6, r5    //r6=(r1<<1)&0xeeeeeeee
    mov      r8, r8    //clear HD

    lsrs     r7, r1, #3//r7=(r1>>3)
    bics     r7, r5
    mov      r8, r8    //clear HD
    eors     r6, r7    //r6=((r1<<1)&mask)^bic(r1>>3,mask)=(r1<<<1)
    mov      r9, r6    //r9=(r1<<<1)
    mov      r7, r8    //clear r7

    //x2=a*(b<<<1)
    ands     r6, r0    //r6=a*(b<<<1)=x2
    mov      r10, r6   //r10=x2

    //rotation of a by 1
    mov      r6, r8    //Clear r6
    lsls     r6, r0, #1//r6=r0<<1
    ands     r6, r5    //r6=(r0<<1)&0xeeeeeeee
    mov      r8, r8    //clear HD
    lsrs     r7, r0, #3//r7=(r0>>3)
    bics     r7, r5
    mov      r8, r8    //clear HD
    eors     r6, r7    //r6=((r0<<1)&mask)^bic(r0>>3,mask)=(r0<<<1)

    ands     r1, r6    //r1=(a<<<1)*b=x3
    mov      r6, r8    //clear r6
    mov      r6, r10   //r6=x2
    eors     r4, r6    //r4=y1^x2=y2
    eors     r4, r1    //r4=y2^x3=y3
    mov      r6, r8    //clear r6
    mov      r1, r8    //clear r1

    //rotation of r by 1
    mov      r7, r8    //clear r7
    lsls     r6, r3, #1//r6=r3<<1
    ands     r6, r5    //r6=(r3<<1)&0xeeeeeeee
    lsrs     r7, r3, #3//r7=(r3>>3)
    bics     r7, r5
    eors     r6, r7    //r6=((r3<<1)&mask)^bic(r3>>3,mask)=(r3<<<1)
    //y4=y3^(r<<<1)    
    eors     r4, r6    //r4=y3^(r<<1)=y4

    //rotation of b<<<1 by 1
    mov      r1, r9    //r6=b<<<1
    mov      r8, r8    //clear HD
    lsls     r6, r1, #1//r6=r1<<1
    mov      r8, r8    //clear HD
    ands     r6, r5    //r6=(r1<<1)&0xeeeeeeee
    mov      r8, r8    //clear HD
    lsrs     r7, r1, #3//r7=(r1>>3)
    bics     r7, r5
    mov      r8, r8    //clear HD
    eors     r6, r7    //r6=((r1<<1)&mask)^bic(r1>>3,mask)=(b<<<2)
    mov      r7, r8    //clear r7  
    mov      r1, r8    //clear r1
    ands     r6, r0    //x4=a*(b<<<2)
    eors     r4, r6    //c=x4^y4
    
    
    str     r4, [r2]
    movs     r4, #0
    movs     r5, #0
    movs    r6, #0
    movs    r7, #0
    mov     r9, r4
    mov     r10,r4



    pop {r4-r6}
    mov  r9, r4
    mov  r10, r5
    mov  r8, r6
    pop {r4-r7}
    pop  {pc}
.endfunc


.global bdfgss_d4_mult_Right_Trigger
.func bdfgss_d4_mult_Right_Trigger
bdfgss_d4_mult_Right_Trigger:

    push {lr}
    push {r4-r7}
    mov  r4, r9
    mov  r5, r10
    mov  r6, r8
    push {r4-r6}
    movs    r3, #0
    movs    r4, #0
    movs    r5, #0
    movs    r6, #0
    movs    r7, #0
    mov     r8, r4
    mov     r9, r4
    mov     r10,r4

    //r0=&a, r1=&b, r2=r
    //------------------------------------------------------------------------
    // First Computation
    // r0 = a, r1 = b
    //push     {r0}
    //push     {r1}
    // y_1 = x_1 + r
    mov      r4, r0
    //mov      r3, r1
    //mov      r3, r8
    //mov      r3, r8

    ands     r4, r1
    eors     r4, r2//r4=y1
    // ------------------------------------------------------------------------

    //------------------------------------------------------------------------
    // Inner Loop
    // Generate Mask 0x77777777
    movs     r5, #0x77
    lsls     r6, r5,#8
    eors     r5, r6    //r5=0x7777
    lsls     r6, r5,#16//r6=0x77770000
    eors     r5, r6    //r5=0x77777777

    //rotation of b by 1
    mov      r8, r8
    lsrs     r6, r1, #1//r6=b>>1
    mov      r8, r8
    //ands     r6, r5    //r6=(b>>1)&0x77777777
    //lsrs     r7, r5, #3//r7=0x0eeeeeee
    //bics     r1, r7    //r1=r1&0xf1111111
    //lsls     r7, r1, #3//r7=(r1&0xf1111111)<<3
    //eors     r6, r7    //r6=((b>>1)&mask)^((r1&0xf1111111)<<3)=(r1>>>1)
    //mov      r9, r6    //r9=(r1>>>1)

    //x2=a*(b>>>1)
    //ands     r6, r0    //r6=a*(b>>>1)=x2
    //mov      r10, r6   //r10=x2

    //rotation of a by 1
    //mov      r6, r8    //Clear r6//71
    //lsrs     r6, r0, #1//r6=r0>>1
    //ands     r6, r5    //r6=(r0>>1)&0x77777777
    //lsrs     r7, r5, #3//r7=0x0eeeeeee
    //bics     r0, r7    //r0=r0&0xf1111111
    //lsls     r7, r0, #3//r7=(r0&0xf1111111)<<3
    //eors     r6, r7    //r6=((r0>>1)&mask)^((r0&mask)<<3)=(r0>>>1)

    //pop      {r1}
    //ands     r1, r6    //r1=(a<<<1)*b=x3
    //eors     r6, r6    //clear r6
    //mov      r6, r10   //r6=x2
    //eors     r4, r6    //r4=y1^x2=y2
    //eors     r4, r1    //r4=y2^x3=y3
    //mov      r1, r8    //clear r1//52
    //pop      {r0}
    //rotation of r by 1
    //lsrs     r6, r2, #1//r6=r3>>1
    //ands     r6, r5    //r6=(r3>>1)&0x77777777
    //lsrs     r7, r5, #3//r7=0x0eeeeeee
    //bics     r2, r7    //r3=r3&0xf1111111
    //lsls     r7, r2, #3//r7=(r3&0xf1111111)<<3    
    //eors     r6, r7    //r6=((r3>>1)&mask)^((r3&mask)<<3)=(r3>>>1)
    //y4=y3^(r>>>1)    
    //eors     r4, r6    //r4=y3^(r<<1)=y4

    //rotation of b>>>1 by 1
    //mov      r1, r9    //r1=b>>>1//40
    //lsrs     r6, r1, #1//r6=r1>>1//37
    //ands     r6, r5    //r6=(r1>>1)&0x77777777
    //lsrs     r7, r5, #3//r7=0x0eeeeeee//
    //bics     r1, r7    //r1=r1&0xf1111111
    //lsls     r7, r1, #3//r7=(r1&0xf1111111)<<3
    //eors     r6, r7    //r6=((r1>>1)&mask)^bic(r1<<3,mask)=(b>>>2)//
    //ands     r6, r0    //x4=a*(b<<<2)
    //eors     r4, r6    //c=x4^y4
    
    
    mov      r0, r8
    //mov      r0, r4
    mov     r4, r8
    mov     r5, r8
    mov    r6, r8
    mov    r7, r8
    //mov     r9, r4
    //mov     r10,r4

  @Start of trigger
  @Trigger address: 0x50013FFC
  movs r4, #80
  lsls r4, r4, #8
  movs r5, #0
  eors r4, r5  //0x5000
  lsls r4, #16 //0x50000000
  movs r5, #63 //0x3f
  lsls r5,r5,#8 //0x3f00
  eors r4,r5    //0x50013f00
  movs r5, #252
  eors r4,r5    //0x50013ffc
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


    pop {r4-r6}
    mov  r9, r4
    mov  r10, r5
    mov  r8, r6
    pop {r4-r7}
    pop  {pc}

.endfunc

.end

