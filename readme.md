# MODA - Modular AES

[![Build Status](https://travis-ci.org/cjhdev/moda.svg?branch=master)](https://travis-ci.org/cjhdev/moda)

An easy to integrate AES implementation for resource constrained targets.

Highlights:

- Source linted to MISRA 2012
- Embedded interface documentation
- Tests
- Compile time options for porting

## Modules

- AES
    - byte oriented (512B of tables)
    - support for 128, 196 and 256 bit keys
- AES GCM
    - depends on AES
    - table-less
    - vector operations optimised for target word size
    - single pass mode only
- AES Key Wrap
    - depends on AES
    - RFC 3394:2002
- AES CMAC
    - depends on AES
    - vector operations optimised for target word size
    - NIST SP 800-38B
    - single pass mode only

## Integrating With Your Project

Example makefile snippet:

~~~ mf
INCLUDES += $(DIR_MODA)/include

VPATH += $(DIR_MODA)/src

SRC += $(wildcard $(DIR_MODA)/src/*.c)

OBJECTS += $(SRC:.c=.o)
~~~

Add `#include "moda.h"` to source files that use the MODA API.

## Build Time Options

~~~
// define to remove assert.h (as per usual)
-DNDEBUG

// define to set target endian as big endian
// default: undefined (not relevant if MODA_WORD_SIZE == 1)
-DMODA_BIG_ENDIAN

// define to set target word size {1, 2, 4 or 8}
// default: 1
-DMODA_WORD_SIZE=4

// define to apply compiler specific restrict attribute
// default: __restrict__
-DMODA_RESTRICT=__restrict__

// include settings for putting constant data into program memory for avr gcc
// default: undefined
-DMODA_AVR_GCC_PROGMEM

// define to apply target specific attribute after sbox, rsbox and rcon constants
// default: undefined
-DMODA_CONST_POST=PROGMEM

// define to apply target specific attribute before sbox, rsbox and rcon constants
// default: undefined
-D'MODA_CONST_PRE=__flash'

// define an alternate instruction to use to access rsbox constant
// default: rsbox[C]
-D'RSBOX(C)=pgm_read_byte(&rsbox[C])'

// define an alternate instruction to use to access sbox constant
// default: sbox[C]
-D'SBOX(C)=pgm_read_byte(&sbox[C])'

// define an alternate instruction to use to access rcon constant
// default: rcon[C]
-D'RCON(C)=pgm_read_byte(&rcon[C])'

~~~

## Recommended Further Reading

[https://en.wikipedia.org/wiki/Side-channel_attack](https://en.wikipedia.org/wiki/Side-channel_attack)

## License

Moda has an MIT license.

