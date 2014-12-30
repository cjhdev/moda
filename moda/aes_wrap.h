#ifndef AES_WRAP_H
#define AES_WRAP_H
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
 * @defgroup moda_aes_wrap AES Wrap Algorithm (RFC 3394:2002)
 * @{
 *
 * AES Wrap Algorithm (RFC 3394:2002)
 *
 * */
#include <stdint.h>

/** forward declaration */
struct aes_ctxt;

/** Wrap input
 *
 * - input must be a multiple of 8 bytes and at least 8 bytes
 * - output buffer must be large enough to accommodate (in_size + 8) bytes
 * - output may be the same memory address as input
 * - iv may be NULL to use the default IV
 *
 * @param aes AES context
 * @param out output buffer
 * @param in input buffer
 * @param inSize size of in (in bytes)
 * @param iv 8 byte IV field (NULL for default)
 *
 * */
void MODA_AES_WRAP_Encrypt(const struct aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint16_t inSize, const uint8_t *iv);

/** Unwrap input
 * 
 * - input must be a multiple of 8 bytes and at least 16 bytes
 * - output buffer must be large enough to accommodate (in_size - 8) bytes
 * - output may be the same memory address as input
 * - iv may be NULL to use the default IV
 *
 * @param aes AES context
 * @param out output buffer
 * @param in input buffer
 * @param inSize size of in (in bytes)
 * @param iv 8 byte IV field (NULL for default)
 *
 * @return validation result
 * @retval MODA_RETVAL_PASS
 * @retval MODA_RETVAL_FAIL
 *
 * */
uint8_t MODA_AES_WRAP_Decrypt(const struct aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint16_t inSize, const uint8_t *iv);

/** @} */
/** @} */
#endif

