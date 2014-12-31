# MODA - Modular AES

An easy to integrate cryptographic implementation.

Modules:

- AES
    - byte oriented (512B of tables)
    - support for 128, 196 and 256 bit keys
- AES ECB
    - depends on AES
- AES GCM
    - depends on AES
    - table-less
    - vector operations optimised for target word size
    - single pass mode only (no starting and stopping)
- AES WRAP
    - depends on AES
    - RFC 3394:2002

## Compile Time Options

    // define to remove assert.h (as per usual)
    -DNDEBUG

    // define to set target endian as little endian
    -DMODA_LITTLE_ENDIAN

    // define to set target word size {1, 2, 4 or 8}; default 1
    -DMODA_WORD_SIZE=4

## License

Contents of /moda is covered by the MIT License. Terms and conditions
are published in each source file.

Cameron Harper 2013-2014
cam@cjh.id.au



