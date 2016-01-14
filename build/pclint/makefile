DIR_ROOT := ../..

DIR_SRC := $(DIR_ROOT)/src
DIR_INCLUDE := $(DIR_ROOT)/include
DIR_SETTINGS := settings

PCLINT_LIB := /usr/local/lib/pclint
PCLINT_BIN := /usr/local/bin/pclint

CC := gcc
GXX := g++

DEFINES := -dMODA_RESTRICT=__restrict__

SRC := $(shell ls $(DIR_SRC))

CFLAGS := -std=c99

# rules to apply (order is significant)
RULES := au-misra.lnt co-gcc.lnt settings.lnt 

# this will ensure the settings folder is initialised (or re-initialised)
install: clean_settings gen_settings

# run co-gcc.mak to gather toolchain settings in the pclint folder
gen_settings:
	cd $(DIR_SETTINGS) && make -f $(PCLINT_LIB)/lnt/co-gcc.mak GCC_BIN=$(CC) GXX_BIN=$(GXX) CFLAGS=$(CFLAGS) CXXFLAGS=$(CXXFLAGS) CPPFLAGS=$(CPPFLAGS) COMMON_FLAGS=$(COMMON_FLAGS)

# clear contents of pclint folder
clean_settings:
	rm -f $(DIR_SETTINGS)/*.lnt $(DIR_SETTINGS)/*.h

# lint the source
lint:
	$(PCLINT_BIN) "+rw(__is_pod)" $(DEFINES) -I$(PCLINT_LIB)/lnt -I$(DIR_SETTINGS) -I$(DIR_INCLUDE) -I$(DIR_SRC) $(RULES) $(SRC)




