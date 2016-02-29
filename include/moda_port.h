/* Copyright (c) 2013-2016 Cameron Harper
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * */
#ifndef MODA_PORT_H
#define MODA_PORT_H

/**
 * @defgroup moda_port Porting options for Modular AES
 * @ingroup moda
 *
 * MODA defines for porting
 *
 * @{
 * */

/* only included for documentation */
#ifdef DOXYGEN

    /** define to remove ASSERT from source @note default is undefined */
    #define NDEBUG

    /** define to set target word size to 1, 2, 4 or 8 @note default is 1 */
    #define MODA_WORD_SIZE

    /** define to apply compiler specific restrict attribute @note default is undefined */
    #define MODA_RESTRICT __restrict__

    /** define to include settings for putting constant data into program memory for avr gcc @note default is undefined */
    #define MODA_AVR_GCC_PROGMEM

    /** define to apply target specific attribute after sbox, rsbox and rcon constants @note default is undefined */
    #define MODA_CONST_POST PROGMEM

    /** define to apply target specific attribute before sbox, rsbox and rcon constants @note default is undefined */
    #define MODA_CONST_PRE PROGMEM __flash

    /** define an alternate instruction to use to access rsbox constant @note default is `rsbox[C]` */    
    #define RSBOX(C) pgm_read_byte(&rsbox[C])

    /** define an alternate instruction to use to access sbox constant @note default is `sbox[C]` */
    #define SBOX(C) pgm_read_byte(&sbox[C])

    /** define an alternate instruction to use to access rcon constant @note default is `rcon[C]` */    
    #define RCON(C) pgm_read_byte(&rcon[C])

#else

    #ifdef MODA_AVR_GCC_PROGMEM

        #include <avr/pgmspace.h>
        
        #define MODA_CONST_POST PROGMEM
        #define RSBOX(C) pgm_read_byte(&rsbox[C])
        #define SBOX(C) pgm_read_byte(&sbox[C])
        #define RCON(C) pgm_read_byte(&rcon[C])

    #endif

#endif    


/** @} */
#endif
