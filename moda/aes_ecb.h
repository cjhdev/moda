#ifndef AES_ECB_H
#define AES_ECB_H
/**
 * @file
 *
 * AES ECB Mode
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
 * @defgroup moda_aes_ecb AES ECB Mode
 * @{
 *
 * */
#include <stdint.h>

/** forward declaration */
struct aes_ctxt;

/**
 * AES ECB Encrypt
 *
 * @param[in] aes context
 * @param[out] out output buffer
 * @param[in] in buffer (may be aligned with out)
 * @param[in] size size of in (in bytes)
 *
 * */
void MODA_AES_ECB_Encrypt(const struct aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint32_t size);

/**
 * AES ECB Decrypt
 *
 * @param[in] aes AES context
 * @param[out] out output buffer
 * @param[in] in buffer (may be aligned with out)
 * @param[in] size size of in (in bytes)
 *
 * */
void MODA_AES_ECB_Decrypt(const struct aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint32_t size);

/** @} */
/** @} */
#endif

