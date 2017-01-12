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
#ifndef MODA_INTERNAL_H
#define MODA_INTERNAL_H

#ifdef NDEBUG
    #define ASSERT(X)
#else
    #include <assert.h>
    #define ASSERT(X) assert(X);
#endif

#ifndef MODA_WORD_SIZE
    #define MODA_WORD_SIZE 1U
#endif

#if (MODA_WORD_SIZE == 1U)
typedef uint8_t moda_word_t;
#elif (MODA_WORD_SIZE == 2U)
typedef uint16_t moda_word_t;
#elif (MODA_WORD_SIZE == 4U)
typedef uint32_t moda_word_t;
#elif (MODA_WORD_SIZE == 8U)
typedef uint64_t moda_word_t;
#else
    #error "unknown word size"
#endif

#ifndef MODA_RESTRICT
    #define MODA_RESTRICT __restrict__
#endif

#endif
