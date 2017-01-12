DIR_ROOT := ..
DIR_CMOCKA := $(DIR_ROOT)/vendor/cmocka
DIR_BUILD := build
DIR_BIN := bin

CC := gcc

VPATH += $(DIR_ROOT)/src
VPATH += $(DIR_CMOCKA)/src

INCLUDES += -I$(DIR_ROOT)/include
INCLUDES += -I$(DIR_CMOCKA)/include

CMOCKA_DEFINES += -DHAVE_STRINGS_H
CMOCKA_DEFINES += -DHAVE_SIGNAL_H
CMOCKA_DEFINES += -DHAVE_INTTYPES_H
CMOCKA_DEFINES += -DHAVE_MALLOC_H

MODA_WORD_SIZE := 1

MODA_DEFINES := -DMODA_WORD_SIZE=$(MODA_WORD_SIZE)

CFLAGS := -Wall -Werror -g -fprofile-arcs -ftest-coverage $(INCLUDES) $(CMOCKA_DEFINES) $(MODA_DEFINES)
LDFLAGS := -fprofile-arcs -g

SRC_MODA := $(notdir $(wildcard $(DIR_ROOT)/src/*.c))
SRC_CMOCKA := $(notdir $(wildcard $(DIR_CMOCKA)/src/*.c))

OBJ_MODA := $(SRC_MODA:.c=.o)
OBJ_CMOCKA := $(SRC_CMOCKA:.c=.o)

TESTS := $(basename $(wildcard test_*.c))

.PHONY: clean build_and_run 

all: $(addprefix run_, $(TESTS))

run_%: $(addprefix $(DIR_BIN)/, %)
	@ echo ""
	@ echo "running '$^'..."
	@ echo ""
	- @ ./$^

$(DIR_BIN)/test_%: $(addprefix $(DIR_BUILD)/, test_%.o $(OBJ_MODA) $(OBJ_CMOCKA))
	echo $^
	$(CC) $(LDFLAGS) $^ -o $@

$(DIR_BUILD)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(DIR_BUILD)/*
