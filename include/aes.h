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

 /** @file
 * 
 * Interface to the AES Block Cipher
 *
 * @copyright
 *
 * Cameron Harper 2013-2016
 * 
 * @license
 *
 * MIT
 *
 * */
#ifndef AES_H
#define AES_H

#include <stdint.h>

/** block cipher size in bytes */
#define AES_BLOCK_SIZE  16U

/** AES key sizes supported by AES modes */
enum aes_key_size {

    AES_KEY_128 = 16U,  /**< AES-128 */
    AES_KEY_192 = 24U,  /**< AES-198 */
    AES_KEY_256 = 32U   /**< AES-256 */
};

/** AES context */
struct aes_ctxt {

    uint8_t k[240U];    /**< expanded key */
    uint8_t r;          /**< number of rounds */
};

/**
 * Initialise an AES block cipher
 *
 * @param[in] aes context
 * @param[in] keySize size of the key
 * @param[in] key pointer to the key (any alignment)
 * 
 * */
void MODA_AES_Init(struct aes_ctxt *aes, enum aes_key_size keySize, const uint8_t *key);

/**
 * Encrypt state
 *
 * @param[in] aes context
 * @param[in] s AES_BLOCK_SIZE bytes of state
 * 
 * */
void MODA_AES_Encrypt(const struct aes_ctxt *aes, uint8_t *s);

/**
 * Decrypt state
 *
 * @param[in] aes context
 * @param[in] s AES_BLOCK_SIZE bytes of state
 *
 * */
void MODA_AES_Decrypt(const struct aes_ctxt *aes, uint8_t *s);

#endif
