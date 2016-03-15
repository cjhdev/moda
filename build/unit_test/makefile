DIR_ROOT := ../..

CC := gcc

DIR_BUILD := build
DIR_BIN := bin

DIR_UNITY := $(DIR_ROOT)/tools/unity

DIR_RUNNERS := runners

DIR_MODULE_MODA := $(DIR_ROOT)

VPATH := $(DIR_MODULE_MODA)/src:$(DIR_MODULE_MODA)/test/unit_test:$(DIR_UNITY)/src:$(DIR_RUNNERS)

INCLUDES := -I$(DIR_MODULE_MODA)/include -I$(DIR_UNITY)/src

# define WORD_SIZE as an argument to make to set MODA_WORD_SIZE=[1|2|4|8]
DEFINES := -DMODA_RESTRICT=__restrict__ -DMODA_LITTLE_ENDIAN=$(WORD_SIZE)

CFLAGS := -O2 -Wall -pedantic -std=c99 -g -fprofile-arcs -ftest-coverage $(INCLUDES) $(DEFINES)
LDFLAGS := -fprofile-arcs

SRC_UNITY := unity.c

TEST_FILES := $(shell ls $(DIR_MODULE_MODA)/test/unit_test)

TESTS := $(TEST_FILES:.c=)
TEST_RUNNERS := $(addprefix run_, $(TESTS))

all: clean run

runners: $(addprefix $(DIR_RUNNERS)/, $(TEST_RUNNERS:=.c))

$(DIR_RUNNERS)/run_%.c: %.c
	ruby $(DIR_UNITY)/auto/generate_test_runner.rb $(^) $(@)

#
# In this verbose approach there is one recipe per test
#

tests: $(TESTS)

test_aes:  $(addprefix $(DIR_BUILD)/, test_aes.o aes.o unity.o run_test_aes.o)
	$(CC) $(LDFLAGS) $^ -o $(DIR_BIN)/$@

test_aes_gcm:  $(addprefix $(DIR_BUILD)/, test_aes_gcm.o aes.o aes_gcm.o unity.o run_test_aes_gcm.o)
	$(CC) $(LDFLAGS) $^ -o $(DIR_BIN)/$@

test_aes_wrap:  $(addprefix $(DIR_BUILD)/, test_aes_wrap.o aes.o aes_wrap.o unity.o run_test_aes_wrap.o)
	$(CC) $(LDFLAGS) $^ -o $(DIR_BIN)/$@

test_aes_cmac: $(addprefix $(DIR_BUILD)/, test_aes_cmac.o aes.o aes_cmac.o unity.o run_test_aes_cmac.o)
	$(CC) $(LDFLAGS) $^ -o $(DIR_BIN)/$@

$(DIR_BUILD)/%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY: clean clean_obj clean_runners clean_bin

clean: clean_obj clean_runners clean_bin

clean_obj:
	rm -f $(DIR_BUILD)/*

clean_runners:
	rm -f $(DIR_RUNNERS)/*

clean_bin:
	rm -f $(DIR_BIN)/*

run: $(addprefix run_, $(TESTS))

run_%: %
	./$(DIR_BIN)/$^
	gcov --no-output --object-directory $(DIR_BUILD) $(DIR_BUILD)/$(subst test_,,$^).gcda
