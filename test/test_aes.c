/* Copyright (c) 2014 Cameron Harper
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
 * @example test_aes.c
 *
 * Tests from FIPS-197
 *
 * */


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "cmocka.h"

#include "aes.h"

#include <string.h>

static void test_MODA_AES_Init(void **user)
{
    struct aes_ctxt aes;
    static const uint8_t key[] = {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11};

    MODA_AES_Init(&aes, AES_KEY_128, key);
    MODA_AES_Init(&aes, AES_KEY_192, key);
    MODA_AES_Init(&aes, AES_KEY_256, key);
}



static void test_MODA_AES_Encrypt_128(void **user)
{
    static const uint8_t key[] = {0x10,0xa5,0x88,0x69,0xd7,0x4b,0xe5,0xa3,0x74,0xcf,0x86,0x7c,0xfb,0x47,0x38,0x59};
    static const uint8_t pt[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const uint8_t ct[] = {0x6d,0x25,0x1e,0x69,0x44,0xb0,0x51,0xe0,0x4e,0xaa,0x6f,0xb4,0xdb,0xf7,0x84,0x65};

    struct aes_ctxt aes;
    uint8_t out[AES_BLOCK_SIZE];

    memcpy(out, pt, sizeof(out));
    MODA_AES_Init(&aes, AES_KEY_128, key);
    MODA_AES_Encrypt(&aes, out);

    assert_memory_equal(ct, out, sizeof(ct));
}

static void test_MODA_AES_Encrypt_192(void **user)
{
    static const uint8_t key[] = {0xe9,0xf0,0x65,0xd7,0xc1,0x35,0x73,0x58,0x7f,0x78,0x75,0x35,0x7d,0xfb,0xb1,0x6c,0x53,0x48,0x9f,0x6a,0x4b,0xd0,0xf7,0xcd};
    static const uint8_t pt[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const uint8_t ct[] = {0x09,0x56,0x25,0x9c,0x9c,0xd5,0xcf,0xd0,0x18,0x1c,0xca,0x53,0x38,0x0c,0xde,0x06};

    struct aes_ctxt aes;
    uint8_t out[AES_BLOCK_SIZE];

    memcpy(out, pt, sizeof(out));
    MODA_AES_Init(&aes, AES_KEY_192, key);
    MODA_AES_Encrypt(&aes, out);

    assert_memory_equal(ct, out, sizeof(ct));
}

static void test_MODA_AES_Encrypt_256(void **user)
{
    static const uint8_t key[] = {0xc4,0x7b,0x02,0x94,0xdb,0xbb,0xee,0x0f,0xec,0x47,0x57,0xf2,0x2f,0xfe,0xee,0x35,0x87,0xca,0x47,0x30,0xc3,0xd3,0x3b,0x69,0x1d,0xf3,0x8b,0xab,0x07,0x6b,0xc5,0x58};
    static const uint8_t pt[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const uint8_t ct[] = {0x46,0xf2,0xfb,0x34,0x2d,0x6f,0x0a,0xb4,0x77,0x47,0x6f,0xc5,0x01,0x24,0x2c,0x5f};

    struct aes_ctxt aes;
    uint8_t out[AES_BLOCK_SIZE];

    memcpy(out, pt, sizeof(out));
    MODA_AES_Init(&aes, AES_KEY_256, key);
    MODA_AES_Encrypt(&aes, out);

    assert_memory_equal(ct, out, sizeof(ct));
}

static void test_MODA_AES_Decrypt_128(void **user)
{
    static const uint8_t key[] = {0x10,0xa5,0x88,0x69,0xd7,0x4b,0xe5,0xa3,0x74,0xcf,0x86,0x7c,0xfb,0x47,0x38,0x59};
    static const uint8_t pt[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const uint8_t ct[] = {0x6d,0x25,0x1e,0x69,0x44,0xb0,0x51,0xe0,0x4e,0xaa,0x6f,0xb4,0xdb,0xf7,0x84,0x65};

    struct aes_ctxt aes;
    uint8_t out[AES_BLOCK_SIZE];

    memcpy(out, ct, sizeof(out));
    MODA_AES_Init(&aes, AES_KEY_128, key);
    MODA_AES_Decrypt(&aes, out);

    assert_memory_equal(pt, out, sizeof(pt));
}

static void test_MODA_AES_Decrypt_192(void **user)
{
    static const uint8_t key[] = {0xe9,0xf0,0x65,0xd7,0xc1,0x35,0x73,0x58,0x7f,0x78,0x75,0x35,0x7d,0xfb,0xb1,0x6c,0x53,0x48,0x9f,0x6a,0x4b,0xd0,0xf7,0xcd};
    static const uint8_t pt[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const uint8_t ct[] = {0x09,0x56,0x25,0x9c,0x9c,0xd5,0xcf,0xd0,0x18,0x1c,0xca,0x53,0x38,0x0c,0xde,0x06};

    struct aes_ctxt aes;
    uint8_t out[AES_BLOCK_SIZE];

    memcpy(out, ct, sizeof(out));
    MODA_AES_Init(&aes, AES_KEY_192, key);
    MODA_AES_Decrypt(&aes, out);

    assert_memory_equal(pt, out, sizeof(pt));
}

static void test_MODA_AES_Decrypt_256(void **user)
{
    static const uint8_t key[] = {0xc4,0x7b,0x02,0x94,0xdb,0xbb,0xee,0x0f,0xec,0x47,0x57,0xf2,0x2f,0xfe,0xee,0x35,0x87,0xca,0x47,0x30,0xc3,0xd3,0x3b,0x69,0x1d,0xf3,0x8b,0xab,0x07,0x6b,0xc5,0x58};
    static const uint8_t pt[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    static const uint8_t ct[] = {0x46,0xf2,0xfb,0x34,0x2d,0x6f,0x0a,0xb4,0x77,0x47,0x6f,0xc5,0x01,0x24,0x2c,0x5f};

    struct aes_ctxt aes;
    uint8_t out[AES_BLOCK_SIZE];

    memcpy(out, ct, sizeof(out));
    MODA_AES_Init(&aes, AES_KEY_256, key);
    MODA_AES_Decrypt(&aes, out);

    assert_memory_equal(pt, out, sizeof(pt));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_MODA_AES_Init),
        cmocka_unit_test(test_MODA_AES_Encrypt_128),        
        cmocka_unit_test(test_MODA_AES_Encrypt_192),        
        cmocka_unit_test(test_MODA_AES_Encrypt_256),        
        cmocka_unit_test(test_MODA_AES_Decrypt_128),        
        cmocka_unit_test(test_MODA_AES_Decrypt_192),        
        cmocka_unit_test(test_MODA_AES_Decrypt_256)     
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

