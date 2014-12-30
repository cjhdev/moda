/* Copyright (c) 2013-2014 Cameron Harper
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

/* includes ***********************************************************/

#include "aes.h"
#include "aes_gcm.h"
#include "moda.h"

/* defines ************************************************************/

#ifdef NDEBUG

    /*lint -e(9026) Allow assert to be removed completely */
    #define ASSERT(X) ;

#else

    #include <stddef.h>
    #include <assert.h>

    /*lint -e(9026) Allow assert to be removed completely */
    #define ASSERT(X) /*lint -e(9034)*/assert(X);

#endif

#ifndef MODA_WORD_SIZE
    #define MODA_WORD_SIZE 1U
#endif

#if (MODA_WORD_SIZE == 1U)
typedef uint8_t moda_word_t;
#elif (MODA_WORD_SIZE == 2U)
typedef uint16_t moda_word_t;
#elif (MODA_WORD_SIZE == 4U)
typedef uint32_t moda_word_t;
#elif (MODA_WORD_SIZE == 8U)
typedef uint64_t moda_word_t;
#else
    #error "unknown word size"
#endif

#define WORD_BLOCK_SIZE (AES_BLOCK_SIZE / MODA_WORD_SIZE)

#define TRUE 1U
#define FALSE 0U

#ifdef MODA_LITTLE_ENDIAN

    #define R   0xe1U

    #if (MODA_WORD_SIZE == 1U)
        #define TST_MSB 0x01U
        #define LSB 0x80U
    #elif (MODA_WORD_SIZE == 2U)
        #define TST_MSB 0x0100U
        #define LSB 0x8000U
    #elif (MODA_WORD_SIZE == 4U)
        #define TST_MSB 0x01000000U
        #define LSB 0x80000000U
    #else
        #define TST_MSB 0x0100000000000000U
        #define LSB 0x8000000000000000U
    #endif

#else

    #define TST_MSB 0x01U

    #if (MODA_WORD_SIZE == 1U)
        #define R 0xe1U
        #define LSB 0x80U
    #elif (MODA_WORD_SIZE == 2U)
        #define R 0xe100U
        #define LSB 0x8000U
    #elif (MODA_WORD_SIZE == 4U)
        #define R 0xe1000000U
        #define LSB 0x80000000U
    #else
        #define R 0xe100000000000000U
        #define LSB 0x8000000000000000U
    #endif

#endif

/* private prototypes *************************************************/

/**
 * Equivalent to memcpy
 *
 * @param[out] acc accumulator
 * @param[in] mask XORed with accumulator
 *
 * */
static void localMemcpy(uint8_t *s1, const uint8_t *s2, uint8_t n);

/**
 * Equivalent to memset
 *
 * @param[out] acc accumulator
 * @param[in] mask XORed with accumulator
 *
 * */
static void localMemset(uint8_t *s, const uint8_t c, uint8_t n);

/**
 * Equivalent to memcmp
 *
 * @param[out] acc accumulator
 * @param[in] mask XORed with accumulator
 *
 * */
static uint8_t localMemcmp(const uint8_t *s1, const uint8_t *s2, uint8_t n);

/**
 * XOR an aligned AES block
 *
 * @param[out] acc accumulator
 * @param[in] mask XORed with accumulator
 *
 * */
static void xor128(moda_word_t *acc, const moda_word_t *mask);

/**
 * Word copy an aligned AES block
 *
 * @param[out] to copy destination
 * @param[in] from copy input
 *
 * */
static void copy128(moda_word_t *to, const moda_word_t *from);

#if (MODA_WORD_SIZE > 1U)
#ifdef MODA_LITTLE_ENDIAN
/**
 * Swap the byte endianness of a word
 *
 * @param[in] w input word
 * @return reversed word
 *
 * */
static moda_word_t swapw(moda_word_t w);

/**
 * Swap the byte endianness of an AES block
 *
 * @param[in] block block to swap
 *
 * */
static void swapBlock(moda_word_t *block);
#endif
#endif

/**
 * @param[in] y accumulator
 * @param[in] 
 *
 * */
static void mul128(moda_word_t *x, const moda_word_t *y);

/**
 * Increment an unaligned big endian 32bit counter
 *
 * @param[in] counter pointer to MSB of counter field
 *
 * */
static void incrementCounter(uint8_t *counter);

/**
 * GCM implementation
 *
 * @param[in] aes context
 * @param[in] iv initialisation vector
 * @param[in] ivSize size of *IV in bytes
 * @param[out] out cipher output buffer
 * @param[in] in cipher input buffer
 * @param[in] textSize size of *in or *out in bytes
 * @param[in] aad additional non-ciphered data for authentication
 * @param[in] aadSize size of *aad
 * @param[in] encrypt encrypt/decrypt boolean
 * @param[out] XX GMAC output
 * 
 * */
static void gcm(const struct aes_ctxt *aes, const uint8_t *iv, uint32_t ivSize, uint8_t *out, const uint8_t *in, uint32_t textSize, const uint8_t *aad, uint32_t aadSize, uint8_t encrypt, moda_word_t *x);


/* public implementation **********************************************/

void MODA_AES_GCM_Encrypt(const struct aes_ctxt *aes, const uint8_t *iv, uint32_t ivSize, uint8_t *out, const uint8_t *in, uint32_t textSize, const uint8_t *aad, uint32_t aadSize, uint8_t *t, uint8_t tSize)
{
    moda_word_t x[WORD_BLOCK_SIZE];

    ASSERT((aes != NULL))
    ASSERT((tSize <= GCM_TAG_SIZE))
    
    gcm(aes, iv, ivSize, out, in, textSize, aad, aadSize, TRUE, x);
    localMemcpy(t, (uint8_t *)x, tSize);
}

uint8_t MODA_AES_GCM_Decrypt(const struct aes_ctxt *aes, const uint8_t *iv, uint32_t ivSize, uint8_t *out, const uint8_t *in, uint32_t textSize, const uint8_t *aad, uint32_t aadSize, const uint8_t *t, uint8_t tSize)
{
    moda_word_t x[WORD_BLOCK_SIZE];

    ASSERT((aes != NULL))
    ASSERT((tSize <= GCM_TAG_SIZE))
    
    gcm(aes, iv, ivSize, out, in, textSize, aad, aadSize, FALSE, x);

    return localMemcmp((uint8_t *)x, t, tSize);
}

/* private implementation *********************************************/

static void localMemcpy(uint8_t *s1, const uint8_t *s2, uint8_t n)
{
    uint8_t pos = 0U;

    while(pos != n){

        s1[pos] = s2[pos];
        pos++;
    }
}

static void localMemset(uint8_t *s, const uint8_t c, uint8_t n)
{
    uint8_t pos = 0U;
    
    while(pos != n){

        s[pos] = c;
        pos++;
    }
}

static uint8_t localMemcmp(const uint8_t *s1, const uint8_t *s2, uint8_t n)
{
    uint8_t retval = MODA_RETVAL_PASS;
    uint8_t pos = 0U;

    while(pos != n){

        if(s1[pos] != s2[pos]){

            retval = MODA_RETVAL_FAIL;
            break;
        }

        pos++;
    }

    return retval;
}

static void xor128(moda_word_t *acc, const moda_word_t *mask)
{
    for(uint8_t i=0U; i < WORD_BLOCK_SIZE; i++){

        acc[i] ^= mask[i];
    }
}

static void copy128(moda_word_t *to, const moda_word_t *from)
{
    for(uint8_t i=0U; i < WORD_BLOCK_SIZE; i++){

        to[i] = from[i];
    }
}

#if (MODA_WORD_SIZE > 1U)
#ifdef MODA_LITTLE_ENDIAN
static moda_word_t swapw(moda_word_t w)
{
#if MODA_WORD_SIZE == 1U 
    return w;
#elif MODA_WORD_SIZE == 2U
    return ((w >> 8U) & 0xffU) | ((w << 8U) & 0xff00U);    
#elif MODA_WORD_SIZE == 4U
    return  ((w << 24U) & 0xff000000U)    |
            ((w <<  8U) & 0xff0000U)      |
            ((w >>  8U) & 0xff00U)        |
            ((w >> 24U) & 0xffU);
#else
    return  ((w << 56U) & 0xff00000000000000U)    |
            ((w << 40U) & 0xff000000000000U)      |
            ((w << 24U) & 0xff0000000000U)        |
            ((w <<  8U) & 0xff00000000U)          |
            ((w >>  8U) & 0xff000000U)            |
            ((w >> 24U) & 0xff0000U)              |
            ((w >> 40U) & 0xff00U)                |
            ((w >> 56U) & 0xffU);            
#endif
}

static void swapBlock(moda_word_t *block)
{
    for(uint8_t i=0; i < WORD_BLOCK_SIZE; i++){

        block[i] = swapw(block[i]);
    }
}
#endif
#endif

static void mul128(moda_word_t *x, const moda_word_t *y)
{
    /* Table-less galois multiplication in a 128bit field
     *
     * X = X . Y
     *
     * algorithm:
     * 
     * Z <- 0, V <- X
     * for i to 127 do
     *   if Yi == 1 then
     *     Z <- Z XOR V
     *   end if
     *   if V127 = 0 then
     *     V <- rightshift(V)
     *   else
     *     V <- rightshit(V) XOR R
     *   end if
     * end for
     * return Z
     * 
     * */    
    moda_word_t z[WORD_BLOCK_SIZE];
    moda_word_t v[WORD_BLOCK_SIZE];
    moda_word_t yi;
    moda_word_t t;
    moda_word_t tt;
    moda_word_t vmsb;
    moda_word_t carry;
    uint8_t i;
    uint8_t j;
    uint8_t k;

    xor128(z, z);
    copy128(v, x);

    for(i=0U; i < WORD_BLOCK_SIZE; i++){

        yi = y[i];

        for(j=0U; j < (MODA_WORD_SIZE << 3U); j++){

            if((yi & LSB) == LSB){

                xor128(z, v);
            }
            
            /* MSbit of vector */
            vmsb = v[WORD_BLOCK_SIZE-1U] & TST_MSB;
            carry = 0U;
            
            /* rightshift vector */
            for(k=0U; k < WORD_BLOCK_SIZE; k++){

                t = v[k];        

#if (MODA_WORD_SIZE > 1U)
#ifdef MODA_LITTLE_ENDIAN
                t = swapw(t);        
#endif
#endif
                tt = t;
                tt >>= 1U;
                tt |= carry;

#if (MODA_WORD_SIZE > 1U)
#ifdef MODA_LITTLE_ENDIAN
                tt = swapw(tt);        
#endif
#endif
                carry = ((t & 0x1U) == 0x1U) ? LSB : 0x0U;
                v[k] = tt;
            }

            if(vmsb != 0U){

                v[0] ^= R;
            }
            
            yi <<= 1U;            
        }
    }

    copy128(x, z);
}

static void incrementCounter(uint8_t *counter)
{
    counter[AES_BLOCK_SIZE-1U]++;

    if(counter[AES_BLOCK_SIZE-1U] == 0U){

        counter[AES_BLOCK_SIZE-2U]++;

        if(counter[AES_BLOCK_SIZE-2U] == 0U){

            counter[AES_BLOCK_SIZE-3U]++;

            if(counter[AES_BLOCK_SIZE-3U] == 0U){

                counter[AES_BLOCK_SIZE-4U]++;
            }
        }
    }    
}

static void gcm(const struct aes_ctxt *aes, const uint8_t *iv, uint32_t ivSize, uint8_t *out, const uint8_t *in, uint32_t textSize, const uint8_t *aad, uint32_t aadSize, uint8_t encrypt, moda_word_t *x)
{
    static const uint8_t zeroCounter[] = {0U, 0U, 0U, 1U};
    uint8_t counter[AES_BLOCK_SIZE];
    moda_word_t encryptedCounter[WORD_BLOCK_SIZE];
    moda_word_t encryptedInitialCounter[WORD_BLOCK_SIZE];    
    moda_word_t part[WORD_BLOCK_SIZE];
    moda_word_t h[WORD_BLOCK_SIZE];    
    uint8_t sizeBlock[AES_BLOCK_SIZE];
    
    uint32_t size;
    const uint8_t *inPtr;
    uint8_t *outPtr;

    /* generate the hash subkey */
    xor128(h, h);
    MODA_AES_Encrypt(aes, (uint8_t *)h);

#if (MODA_WORD_SIZE > 1U)
#ifdef MODA_LITTLE_ENDIAN
    swapBlock(h);
#endif
#endif

    /* create zero block */
    xor128(x, x);

    if(ivSize == GCM_IV_SIZE){

        localMemcpy(counter, iv, GCM_IV_SIZE);
        localMemcpy(&counter[GCM_IV_SIZE], zeroCounter, (uint8_t)(AES_BLOCK_SIZE - GCM_IV_SIZE));
    }
    /* GHASH(H, {}, IV) */ 
    else{

        size = ivSize;
        inPtr = iv;

        /* create zero block (for this GHASH) */
        xor128((moda_word_t *)counter, (moda_word_t *)counter);

        if(size > 0U){

            for(;;){

                xor128(part, part);
                localMemcpy((uint8_t *)part, inPtr, ((size < AES_BLOCK_SIZE)? (uint8_t)size : AES_BLOCK_SIZE));
                xor128((moda_word_t *)counter, part);
                mul128((moda_word_t *)counter, h);
                
                if(size <= AES_BLOCK_SIZE){

                    break;
                }
                else{

                    inPtr = &inPtr[AES_BLOCK_SIZE];
                    size -= AES_BLOCK_SIZE;              
                }
            }
        }

        xor128((moda_word_t *)sizeBlock, (moda_word_t *)sizeBlock);
        sizeBlock[11] = (uint8_t)(ivSize >> (32U-3U));
        sizeBlock[12] = (uint8_t)(ivSize >> (24U-3U));
        sizeBlock[13] = (uint8_t)(ivSize >> (16U-3U));
        sizeBlock[14] = (uint8_t)(ivSize >> (8U-3U));
        sizeBlock[15] = (uint8_t)(ivSize << 3U);

        xor128((moda_word_t *)counter, (moda_word_t *)sizeBlock);
        mul128((moda_word_t *)counter, h);
    }

    /* encrypt the initial counter value */
    copy128(encryptedInitialCounter, (moda_word_t *)counter);
    MODA_AES_Encrypt(aes, (uint8_t *)encryptedInitialCounter);

    /* GHASH aad */
    if(aadSize > 0U){

        inPtr = aad;
        size = aadSize;
        
        for(;;){

            xor128(part, part);
            localMemcpy((uint8_t *)part, inPtr, ((size < AES_BLOCK_SIZE)?(uint8_t)size:AES_BLOCK_SIZE));

            xor128(x, part);
            mul128(x, h);

            if(size <= AES_BLOCK_SIZE){

                break;
            }
            else{

                inPtr = &inPtr[AES_BLOCK_SIZE];
                size -= AES_BLOCK_SIZE;
            }
        }
    }

    /* encrypt/decrypt and GHASH cipher text */
    if(textSize > 0U){

        inPtr = in;
        outPtr = out;
        size = textSize;

        for(;;){

            incrementCounter(counter);
            copy128(encryptedCounter, (moda_word_t *)counter);
            MODA_AES_Encrypt(aes, (uint8_t *)encryptedCounter);  
            
            xor128(part, part);
            localMemcpy((uint8_t *)part, inPtr, ((size < AES_BLOCK_SIZE)?(uint8_t)size:AES_BLOCK_SIZE));
            
            if(encrypt == FALSE){

                xor128(x, part);
                mul128(x, h);
            }

            xor128(part, encryptedCounter);
            localMemcpy(outPtr, (uint8_t *)part, (size < AES_BLOCK_SIZE)?(uint8_t)size:AES_BLOCK_SIZE);
            
            if(encrypt == TRUE){

                /* zero garbage in unused block portion */
                if(size < AES_BLOCK_SIZE){

                    localMemset(&((uint8_t *)part)[size], 0U, (uint8_t)(AES_BLOCK_SIZE - size));
                }

                xor128(x, part);
                mul128(x, h);
            }
            
            if(size <= AES_BLOCK_SIZE){

                break;
            }
            else{

                inPtr = &inPtr[AES_BLOCK_SIZE];
                outPtr = &outPtr[AES_BLOCK_SIZE];
                size -= AES_BLOCK_SIZE;
            }
        }
    }

    /* make sizeBlock: [aad_size]64 || [size]64 */
    sizeBlock[0] = 0x0U;
    sizeBlock[1] = 0x0U;
    sizeBlock[2] = 0x0U;
    sizeBlock[3] = (uint8_t)(aadSize >> (32U-3U)); /* (x8 bits) */   
    sizeBlock[4] = (uint8_t)(aadSize >> (24U-3U));
    sizeBlock[5] = (uint8_t)(aadSize >> (16U-3U)); 
    sizeBlock[6] = (uint8_t)(aadSize >> (8U-3U));
    sizeBlock[7] = (uint8_t)(aadSize << 3U);
    sizeBlock[8] = 0x0U;
    sizeBlock[9] = 0x0U;
    sizeBlock[10] = 0x0U;
    sizeBlock[11] = (uint8_t)(textSize >> (32U-3U));
    sizeBlock[12] = (uint8_t)(textSize >> (24U-3U));
    sizeBlock[13] = (uint8_t)(textSize >> (16U-3U));
    sizeBlock[14] = (uint8_t)(textSize >> (8U-3U));
    sizeBlock[15] = (uint8_t)(textSize << 3U);

    /* GHASH output with sizeBlock */
    xor128(x, (moda_word_t *)sizeBlock);
    mul128(x, h);

    /* XOR encrypted initial counter with GHASH output */    
    xor128(x, encryptedInitialCounter);
    
    /* clear h on stack */
    xor128(h, h);    
}
    
