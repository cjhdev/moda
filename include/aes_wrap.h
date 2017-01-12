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
#ifndef AES_WRAP_H
#define AES_WRAP_H

/**
 * @defgroup moda_aes_wrap Authenticated AES Wrap Algorithm (RFC 3394:2002)
 * @ingroup moda
 *
 * Interface to authenticated AES wrap algorithm (RFC 3394:2002)
 *
 * @{
 * */
 
#include <stdint.h>
#include <stdbool.h>

/** forward declaration */
struct aes_ctxt;

/** Wrap input
 *
 * @note `inSize` must be a multiple 8 and be equal to or greater than 8
 * @note `out` must be large enough to accomodate `inSize` + 8 bytes
 * @note if `in` == `out` the process will be performed in place
 * @note the internal default IV shall be used if `iv` is set to NULL
 *
 * @param aes block cipher expanded key
 * @param out output buffer
 * @param in input buffer
 * @param inSize byte size of `in`
 * @param iv 8 byte IV field (NULL for default)
 *
 * */
void MODA_AES_WRAP_Encrypt(const struct aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint16_t inSize, const uint8_t *iv);

/** Unwrap input
 *
 * @note this process is able to validate correctness of `out`
 * @note `inSize` must be a multiple 8 and be equal to or greater than 16
 * @note `out` must be large enough to accomodate (`inSize` - 8) bytes
 * @note if `in` == `out` the process will be performed in place
 * @note the internal default IV shall be used if `iv` is set to NULL
 * 
 * @param aes block cipher expanded key
 * @param out output buffer
 * @param in input buffer
 * @param inSize byte size of `in`
 * @param iv 8 byte IV field (NULL for default)
 *
 * @return true if `in` unwrapped successfully
 *
 * */
bool MODA_AES_WRAP_Decrypt(const struct aes_ctxt *aes, uint8_t *out, const uint8_t *in, uint16_t inSize, const uint8_t *iv);

/** @} */
#endif

