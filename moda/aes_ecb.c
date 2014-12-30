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

/* defines ************************************************************/

#ifdef NDEBUG

    /*lint -e(9026) Allow assert to be removed completely */
    #define ASSERT(X) ;

#else

    #include <assert.h>
    #include <stddef.h>

    /*lint -e(9026) Allow assert to be removed completely */
    #define ASSERT(X) /*lint -e(9034)*/assert(X);

#endif

/* private prototypes *************************************************/

static void localMemcpy(uint8_t *s1, const uint8_t *s2, uint8_t n);
static void localMemset(uint8_t *s, const uint8_t c, uint8_t n);

/* public implementation **********************************************/

void MODA_AES_ECB_Encrypt(const struct aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint32_t size)
{
    uint8_t state[AES_BLOCK_SIZE];
    const uint8_t *i = in;
    uint8_t *o = out;
    uint32_t sz = size;

    ASSERT((aes != NULL))
    
    while(sz != 0U){

        ASSERT((out != NULL))
        ASSERT((in != NULL))

        localMemset(state, 0U, AES_BLOCK_SIZE);
        localMemcpy(state, i, (sz > AES_BLOCK_SIZE)?AES_BLOCK_SIZE:(uint8_t)sz);
        MODA_AES_Encrypt(aes, state);
        localMemcpy(o, state, (sz > AES_BLOCK_SIZE)?AES_BLOCK_SIZE:(uint8_t)sz);
    
        if(sz <= AES_BLOCK_SIZE){

            break;
        }

        sz -= AES_BLOCK_SIZE;
        i = &i[AES_BLOCK_SIZE];
        o = &o[AES_BLOCK_SIZE];
    }
}

void MODA_AES_ECB_Decrypt(const struct aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint32_t size)
{
    uint8_t state[AES_BLOCK_SIZE];
    const uint8_t *i = in;
    uint8_t *o = out;
    uint32_t sz = size;

    ASSERT((aes != NULL))

    while(sz != 0U){

        ASSERT((out != NULL))
        ASSERT((in != NULL))

        localMemset(state, 0U, AES_BLOCK_SIZE);
        localMemcpy(state, i, (sz > AES_BLOCK_SIZE)?AES_BLOCK_SIZE:(uint8_t)sz);
        MODA_AES_Decrypt(aes, state);
        localMemcpy(o, state, (sz > AES_BLOCK_SIZE)?AES_BLOCK_SIZE:(uint8_t)sz);
    
        if(sz <= AES_BLOCK_SIZE){

            break;
        }

        sz -= AES_BLOCK_SIZE;
        i = &i[AES_BLOCK_SIZE];
        o = &o[AES_BLOCK_SIZE];
    }
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

