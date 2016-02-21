DIR_ROOT := ../..

LINE := '--------------------------------------------------------------------------------'

CC := gcc

DIR_BUILD := build
DIR_BIN := bin

DIR_UNITY := $(DIR_ROOT)/tools/unity

DIR_RUNNERS := runners

DIR_MODULE_MODA := $(DIR_ROOT)

VPATH := $(DIR_MODULE_MODA)/src

INCLUDES := -I$(DIR_MODULE_MODA)/include -I$(DIR_UNITY)/src

DEFINES := -DMODA_RESTRICT=__restrict__

CFLAGS := -Os -Wall -pedantic -std=c99 $(INCLUDES) $(DEFINES)
LDFLAGS :=

all:
	@echo "try make avr, arm, arm-thumb or msp430"

avr: CC := avr-gcc
avr: CFLAGS += -mmcu=atmega328p -DNDEBUG -DMODA_AVR_GCC_PROGMEM -DMODA_LITTLE_ENDIAN
avr: clean line obj 

arm: CC := arm-none-eabi-gcc
arm: CFLAGS += -DNDEBUG -D'MODA_WORD_SIZE=4' -DMODA_LITTLE_ENDIAN
arm: clean line obj

arm-thumb: CC := arm-none-eabi-gcc
arm-thumb: CFLAGS += -DNDEBUG -D'MODA_WORD_SIZE=4' -mthumb -DMODA_LITTLE_ENDIAN
arm-thumb: clean line obj

msp430: CC := msp430-gcc
msp430: CFLAGS += -DNDEBUG -D'MODA_WORD_SIZE=2'
msp430: clean line obj

obj:  $(addprefix $(DIR_BUILD)/, aes.o aes_gcm.o aes_wrap.o aes_cmac.o)
	size $^

$(DIR_BUILD)/%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

line:
	@echo $(LINE)

.PHONY: clean clean_obj line

clean: clean_obj

clean_obj:
	rm -f $(DIR_BUILD)/*
