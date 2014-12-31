# The global name of this test
TEST_NAME := test_aes

# The directory relative to /test
D := tests/moda/aes

# Source modules under test
SRC_UNDER_TEST := aes.c

VPATH := $(VPATH):$(D)
TEST_MODULES := $(TEST_MODULES) $(TEST_NAME)
CLEAN_MODULES := $(CLEAN_MODULES) clean_$(TEST_NAME)
GENERATE_MODULES := $(GENERATE_MODULES) generate_$(TEST_NAME)

DIR_BUILD := $(D)/build

LOCAL_DECLARE :=

SRC_RUNNER := $(PREFIX_RUNNER)$(TEST_NAME).c

SRC := $(SRC_UNDER_TEST) $(TEST_NAME).c $(SRC_UNITY) $(SRC_RUNNER)
OBJ := $(addprefix $(DIR_BUILD)/, $(SRC:.c=.o))

generate_$(TEST_NAME)_cmd := ruby $(DIR_TOOL)/unity/auto/generate_test_runner.rb $(D)/$(TEST_NAME).c $(D)/$(SRC_RUNNER)
clean_$(TEST_NAME)_cmd := $(RM) $(DIR_BUILD)/*.o $(DIR_BUILD)/*.gcno $(DIR_BUILD)/*.gcda

$(TEST_NAME): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $(DIR_BIN)/$@

$(DIR_BUILD)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

generate_$(TEST_NAME):
	$($@_cmd)

clean_$(TEST_NAME):
	$($@_cmd)

