# MODA - Modular AES

[![Build Status](https://travis-ci.org/cjhdev/moda.svg?branch=master)](https://travis-ci.org/cjhdev/moda)

An easy to integrate AES implementation for resource constrained targets.

Includes:

- Source linted to MISRA 2012
- Embedded interface documentation
- Portable tests
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

## Build Profiles

### build/pclint

- generates lint-nt toolchain configuration
- runs lint-nt over the source
- checks against MISRA 2012 rules

### build/unit_test

- compiles a binary for each test file found in test/unit_test
- depends on Unity and Ruby
- uses gcov for test coverage report

### build/doxygen

- generates doxygen output from include

### build/size

- compiles objects for (gcc) avr, msp430, and arm then gets the size of the unlinked binaries
- useful to for getting an idea of memory requirements

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

See "moda_port.h" for more details.

## Object Size Indication

Will it fit?

These are typical object sizes from the build/size profile:

### AVR

~~~
avr-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -mmcu=atmega328p -DNDEBUG -DMODA_AVR_GCC_PROGMEM -DMODA_LITTLE_ENDIAN -c ../../src/aes.c -o build/aes.o
avr-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -mmcu=atmega328p -DNDEBUG -DMODA_AVR_GCC_PROGMEM -DMODA_LITTLE_ENDIAN -c ../../src/aes_gcm.c -o build/aes_gcm.o
avr-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -mmcu=atmega328p -DNDEBUG -DMODA_AVR_GCC_PROGMEM -DMODA_LITTLE_ENDIAN -c ../../src/aes_wrap.c -o build/aes_wrap.o
avr-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -mmcu=atmega328p -DNDEBUG -DMODA_AVR_GCC_PROGMEM -DMODA_LITTLE_ENDIAN -c ../../src/aes_cmac.c -o build/aes_cmac.o
size build/aes.o build/aes_gcm.o build/aes_wrap.o build/aes_cmac.o
   text	   data	    bss	    dec	    hex	filename
   2701	      0	      0	   2701	    a8d	build/aes.o
   2000	      0	      0	   2000	    7d0	build/aes_gcm.o
    686	      0	      0	    686	    2ae	build/aes_wrap.o
    914	      0	      0	    914	    392	build/aes_cmac.o
~~~

### MSP430

~~~
msp430-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=2' -c ../../src/aes.c -o build/aes.o
msp430-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=2' -c ../../src/aes_gcm.c -o build/aes_gcm.o
msp430-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=2' -c ../../src/aes_wrap.c -o build/aes_wrap.o
msp430-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=2' -c ../../src/aes_cmac.c -o build/aes_cmac.o
size build/aes.o build/aes_gcm.o build/aes_wrap.o build/aes_cmac.o
   text	   data	    bss	    dec	    hex	filename
   2065	      0	      0	   2065	    811	build/aes.o
   1648	      0	      0	   1648	    670	build/aes_gcm.o
    468	      0	      0	    468	    1d4	build/aes_wrap.o
    566	      0	      0	    566	    236	build/aes_cmac.o
~~~

### ARM

~~~
arm-none-eabi-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=4' -DMODA_LITTLE_ENDIAN -c ../../src/aes.c -o build/aes.o
arm-none-eabi-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=4' -DMODA_LITTLE_ENDIAN -c ../../src/aes_gcm.c -o build/aes_gcm.o
arm-none-eabi-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=4' -DMODA_LITTLE_ENDIAN -c ../../src/aes_wrap.c -o build/aes_wrap.o
arm-none-eabi-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=4' -DMODA_LITTLE_ENDIAN -c ../../src/aes_cmac.c -o build/aes_cmac.o
size build/aes.o build/aes_gcm.o build/aes_wrap.o build/aes_cmac.o
   text	   data	    bss	    dec	    hex	filename
   2559	      0	      0	   2559	    9ff	build/aes.o
   1504	      0	      0	   1504	    5e0	build/aes_gcm.o
    628	      0	      0	    628	    274	build/aes_wrap.o
    592	      0	      0	    592	    250	build/aes_cmac.o
~~~

### ARM (THUMB)

~~~
arm-none-eabi-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=4' -mthumb -DMODA_LITTLE_ENDIAN -c ../../src/aes.c -o build/aes.o
arm-none-eabi-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=4' -mthumb -DMODA_LITTLE_ENDIAN -c ../../src/aes_gcm.c -o build/aes_gcm.o
arm-none-eabi-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=4' -mthumb -DMODA_LITTLE_ENDIAN -c ../../src/aes_wrap.c -o build/aes_wrap.o
arm-none-eabi-gcc -Os -Wall -pedantic -std=c99 -I../../include -I../../tools/unity/src -DMODA_RESTRICT=__restrict__ -DNDEBUG -D'MODA_WORD_SIZE=4' -mthumb -DMODA_LITTLE_ENDIAN -c ../../src/aes_cmac.c -o build/aes_cmac.o
size build/aes.o build/aes_gcm.o build/aes_wrap.o build/aes_cmac.o
   text	   data	    bss	    dec	    hex	filename
   1923	      0	      0	   1923	    783	build/aes.o
    972	      0	      0	    972	    3cc	build/aes_gcm.o
    392	      0	      0	    392	    188	build/aes_wrap.o
    400	      0	      0	    400	    190	build/aes_cmac.o
~~~

## Recommended Further Reading

[https://en.wikipedia.org/wiki/Side-channel_attack](https://en.wikipedia.org/wiki/Side-channel_attack)

## License

MIT license. See terms and conditions in each source file.

Copyright 2013-2016 Cameron Harper
