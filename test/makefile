CC := gcc

PREFIX_RUNNER := testrunner_

DIR_TOOL := ../tools
DIR_SRC := ../moda
DIR_INCLUDE := ../moda
DIR_BIN := bin
INCLUDES := -I$(DIR_INCLUDE) -I$(DIR_TOOL)/unity/src

SRC_UNITY := unity.c

FLAGS_COMMON := -O0 -pedantic -Wall -std=c99 -g -fprofile-arcs -ftest-coverage -DMODA_LITTLE_ENDIAN -DMODA_WORD_SIZE=4

CFLAGS := $(FLAGS_COMMON) $(INCLUDES) $(LOCAL_DECLARE)

VPATH := $(DIR_SRC):$(DIR_TOOL)/unity/src

include tests/moda/aes/module.mk
include tests/moda/aes_ecb/module.mk
include tests/moda/aes_wrap/module.mk
include tests/moda/aes_gcm/module.mk

all: $(TEST_MODULES)

generate: $(GENERATE_MODULES)

clean: $(CLEAN_MODULES)
