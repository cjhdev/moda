#ifndef AES_GCM_H
#define AES_GCM_H
/**
 * @file
 * 
 * @copyright
 *
 * Copyright (c) 2013-2014 Cameron Harper
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
 * @addtogroup moda
 * @{
 * 
 * @defgroup moda_aes_gcm AES GCM Mode
 * @{
 *
 * Stream cipher with authentication from single key (NIST 800-38D)
 *
 * */
#include <stdint.h>

/** forward declaration */
struct aes_ctxt;

/** largest possible authentication tag size */
#define GCM_TAG_SIZE 16U

/** nominal IV size */
#define GCM_IV_SIZE 12U

/**
 * AES GCM Decipher
 * 
 * This function may be called with:
 * 1. in and out defined, aad defined
 * 2. in and out null, aad defined
 * 3. in and out defined, aad null
 * 
 * t is always optional. Valid tSize is (0..GCM_TAG_SIZE) octets.
 * If (tSize == 0) then no authentication will be performed.
 *
 * @param aes context
 *
 * @param iv initialisation vector
 * @param ivSize size of initialisation vector (in bytes)
 *
 * @param out output buffer
 * @param in input buffer (may be aligned with *out)
 * @param textSize size of in (in bytes)
 *
 * @param aad additional data authenticated but not ciphered
 * @param aadSize size of aad (in bytes)
 *
 * @param t optional authentication tag input buffer
 * @param tSize size of t (0..GCM_TAG_SIZE bytes)
 *
 * */
void MODA_AES_GCM_Encrypt(const struct aes_ctxt *aes, const uint8_t *iv, uint32_t ivSize, uint8_t *out, const uint8_t *in, uint32_t textSize, const uint8_t *aad, uint32_t aadSize, uint8_t *t, uint8_t tSize);

/**
 * AES GCM Encipher
 *
 * This function may be called with:
 * 1. in and out defined, aad defined
 * 2. in and out null, aad defined
 * 3. in and out defined, aad null
 * 
 * t is always optional. Valid tSize is (0..GCM_TAG_SIZE) octets.
 *
 * @param aes context
 *
 * @param iv initialisation vector
 * @param ivSize size of initialisation vector (octets)
 *
 * @param out output buffer
 * @param in input buffer (may be aligned with *out)
 * @param textSize size of in (in bytes)
 *
 * @param *aad additional data authenticated but not ciphered
 * @param aadSize size of aad (in bytes)
 *
 * @param *t optional authentication tag input buffer
 * @param tSize size of t (0..GCM_TAG_SIZE octets)
 *
 * @return validation result
 *
 * @retval MODA_RETVAL_PASS
 * @retval MODA_RETVAL_FAIL
 *
 * */
uint8_t MODA_AES_GCM_Decrypt(const struct aes_ctxt *aes, const uint8_t *iv, uint32_t ivSize, uint8_t *out, const uint8_t *in, uint32_t textSize, const uint8_t *aad, uint32_t aadSize, const uint8_t *t, uint8_t tSize);

/** @} */
/** @} */
#endif
