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
#ifndef AES_CMAC_H
#define AES_CMAC_H

/**
 * @defgroup moda_aes_cmac AES-CMAC
 * @ingroup moda
 * 
 * Interface to single pass CMAC implementation as defined in NIST SP 800-38B
 *
 * @{
 * */

#include <stdint.h>

/** forward declaration */
struct aes_ctxt;

/**
 * Produce a CMAC in one step starting with an initialised block cipher
 *
 * @param[in] aes block cipher expanded key
 * @param[in] in input buffer to CMAC
 * @param[in] inLen byte length of `in`
 * @param[out] t authentication tag output buffer
 * @param[in] tSize byte length of `t` in range (0..16)
 *
 * */
void MODA_AES_CMAC(const struct aes_ctxt *aes, const uint8_t *in, uint32_t inLen, uint8_t *t, uint8_t tSize);

/** @} */
#endif
