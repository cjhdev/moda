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
#include "aes_wrap.h"
#include "moda.h"
#include <stddef.h>

/* defines ************************************************************/

#ifdef NDEBUG

    /*lint -e(9026) Allow assert to be removed completely */
    #define ASSERT(X) ;

#else

    #include <assert.h>

    /*lint -e(9026) Allow assert to be removed completely */
    #define ASSERT(X) /*lint -e(9034)*/assert(X);

#endif

#define WRAP_BLOCK 8U

/* globals ************************************************************/

static const uint8_t DefaultIV[] = {0xA6U, 0xA6U, 0xA6U, 0xA6U, 0xA6U, 0xA6U, 0xA6U, 0xA6U};

/* private prototypes *************************************************/

static void localMemcpy(uint8_t *s1, const uint8_t *s2, uint8_t n);
static uint8_t localMemcmp(const uint8_t *s1, const uint8_t *s2, uint8_t n);

/* public implementation **********************************************/

void MODA_AES_WRAP_Encrypt(const struct aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint16_t inSize, const uint8_t *iv)
{
    uint8_t b[AES_BLOCK_SIZE];
    uint8_t *r;
    uint16_t i;
    uint16_t j;
    uint16_t t = 1U;
    const uint8_t *ivPtr = iv;
    
    ASSERT(((inSize % WRAP_BLOCK) == 0U))
    ASSERT((inSize >= WRAP_BLOCK))
    
    if(ivPtr == NULL){

        ivPtr = DefaultIV;
    }

    for(i=inSize; (i != 0U); i -= WRAP_BLOCK){

        localMemcpy(&out[i], &in[i - WRAP_BLOCK], WRAP_BLOCK);        
    }

    localMemcpy(b, ivPtr, WRAP_BLOCK);
    
    for(j=0U; j < 6U; j++){

        r = &out[WRAP_BLOCK];
        
        for(i=0U; i < (inSize >> 3U); i++){

            localMemcpy(&b[WRAP_BLOCK], r, WRAP_BLOCK);

            MODA_AES_Encrypt(aes, b);

            b[7] ^= (uint8_t)t;
            b[6] ^= (uint8_t)(t >> WRAP_BLOCK);
            t++;

            localMemcpy(r, &b[WRAP_BLOCK], WRAP_BLOCK);
            
            r = &r[WRAP_BLOCK];            
        }
    }

    localMemcpy(out, b, WRAP_BLOCK);
}

uint8_t MODA_AES_WRAP_Decrypt(const struct aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint16_t inSize, const uint8_t *iv)
{
    uint8_t b[AES_BLOCK_SIZE];
    uint8_t *r;
    uint16_t i;
    uint16_t j;
    uint16_t t;
    uint16_t n = (inSize >> 3U) - 1U;
    const uint8_t *ivPtr = iv;

    ASSERT(((inSize % WRAP_BLOCK) == 0U))
    ASSERT((inSize >= AES_BLOCK_SIZE))
    
    if(ivPtr == NULL){

        ivPtr = DefaultIV;
    }

    localMemcpy(b, in, WRAP_BLOCK);

    for(i=WRAP_BLOCK; i < inSize; i += WRAP_BLOCK){

        localMemcpy(&out[i - WRAP_BLOCK], &in[i], WRAP_BLOCK);        
    }

    t =  (uint16_t)(6U * n);

    for(j=0U; j < 6U; j++){

        r = &out[inSize - AES_BLOCK_SIZE];
    
        for(i=0U; i < n; i++){

            localMemcpy(&b[WRAP_BLOCK], r, WRAP_BLOCK);

            b[7] ^= (uint8_t)t;
            b[6] ^= (uint8_t)(t >> 8U);
            t--;

            MODA_AES_Decrypt(aes, b);
            localMemcpy(r, &b[WRAP_BLOCK], WRAP_BLOCK);
            r -= WRAP_BLOCK;
        }
    }

    return localMemcmp(b, ivPtr, WRAP_BLOCK);
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
