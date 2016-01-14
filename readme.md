# MODA - Modular AES

An easy to integrate AES implementation for resource constrained targets.

Modules:

- AES
    - byte oriented (512B of tables)
    - support for 128, 196 and 256 bit keys
- AES GCM
    - depends on AES
    - table-less
    - vector operations optimised for target word size
    - single pass mode only (no starting and stopping)
- AES WRAP
    - depends on AES
    - RFC 3394:2002

## Build Profiles

### build/pclint

- generates lint-nt toolchain configuration
- runs lint-nt over the source
- checks against MISRA 2012 rules

### build/unit_test

- compiles a binary for each test file found in test/unit_test
- gcov for coverage report

### build/doxygen

- generates doxygen output from include

## Build Time Options

~~~
// define to remove assert.h (as per usual)
-DNDEBUG

// define to set target endian as little endian
// default: undefined (not relevant if MODA_WORD_SIZE == 1)
-DMODA_LITTLE_ENDIAN

// define to set target word size {1, 2, 4 or 8}
// default: 1
-DMODA_WORD_SIZE=4

// define to apply compiler specific restrict attribute
// default: undefined
-DMODA_RESTRICT=__restrict__

// define to apply target specific attribute after sbox, rsbox and rcon constants
// default: undefined
-DMODA_CONST_POST=PROGMEM

// define to apply target specific attribute before sbox, rsbox and rcon constants
// default: undefined
-DMODA_CONST_PRE=__flash

// define an alternate instruction to use to access rsbox constant
// default: rsbox[C]
-DRSBOX(C)=pgm_read_byte(&rsbox[C])

// define an alternate instruction to use to access sbox constant
// default: sbox[C]
-DSBOX(C)=pgm_read_byte(&sbox[C])

// define an alternate instruction to use to access rcon constant
// default: rcon[C]
-DRCON(C)=pgm_read_byte(&rcon[C])

// define target specific includes necessary to make SBOX, RSBOX and RCON macros work
// default: undefined
-DMODA_ARCH_INCLUDE=#include <avr/pgmspace.h>

~~~

## Recommended Further Reading

[https://en.wikipedia.org/wiki/Side-channel_attack](https://en.wikipedia.org/wiki/Side-channel_attack)

## License

MIT license. See terms and conditions in each source file.

Copyright Cameron Harper 2013-2016
cam@cjh.id.au

