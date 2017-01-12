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

/**
 * @defgroup moda_aes_gcm AES-GCM
 * @ingroup moda
 * 
 * Interface to single pass stream cipher with authentication from a single key (NIST SP 800-38D)
 *
 * @{
 * */
#ifndef AES_GCM_H
#define AES_GCM_H

#include <stdint.h>
#include <stdbool.h>

/** forward declaration */
struct aes_ctxt;

/**
 * AES GCM Encrypt
 *
 * @note if `in` == `out` then encryption will be performed in place
 * @note `tSize` is valid in the range (0..16) 
 *
 * @param aes block cipher expanded key
 *
 * @param iv initialisation vector
 * @param ivSize byte size of `iv`
 *
 * @param out output buffer
 * @param in input buffer
 * @param textSize byte size of `in`
 *
 * @param aad additional data authenticated but not encrypted/decrypted
 * @param aadSize byte size of `aad`
 *
 * @param t optional authentication tag input buffer
 * @param tSize byte size of `t`
 *
 * */
void MODA_AES_GCM_Encrypt(const struct aes_ctxt *aes, const uint8_t *iv, uint32_t ivSize, uint8_t *out, const uint8_t *in, uint32_t textSize, const uint8_t *aad, uint32_t aadSize, uint8_t *t, uint8_t tSize);

/**
 * AES GCM Decrypt
 *
 * @note if `in` == `out` then encryption will be performed in place
 * @note `tSize` is valid in the range (0..16) 
 * 
 * @param aes block cipher expanded key
 *
 * @param iv initialisation vector
 * @param ivSize byte size of `iv`
 *
 * @param out output buffer
 * @param in input buffer
 * @param textSize byte size of `in`
 *
 * @param *aad additional data authenticated but not encrypted/decrypted
 * @param aadSize byte size of `aad`
 *
 * @param *t optional authentication tag input buffer
 * @param tSize size of t
 *
 * @return true if input is valid
 *
 * */
bool MODA_AES_GCM_Decrypt(const struct aes_ctxt *aes, const uint8_t *iv, uint32_t ivSize, uint8_t *out, const uint8_t *in, uint32_t textSize, const uint8_t *aad, uint32_t aadSize, const uint8_t *t, uint8_t tSize);

/** @} */
#endif
