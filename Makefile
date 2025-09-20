# For building Northwestern CS213 PackLab
# You don’t need to edit this file, and you probably shouldn’t
# Copied from Northwestern CS211, Northwestern CS343, and Tock libtock-c

# Toolchain configurations

# Debugging. To debug compilation use `make V=1`
V ?= 0
ifneq ($(V), 0)
    Q =
	TRACE_DIR =
	TRACE_CC  =
	TRACE_LD  =
else
    Q = @
	TRACE_DIR = @echo " DIR " $@
	TRACE_CC  = @echo "  CC " $<
	TRACE_LD  = @echo "  LD " $@
endif

# C compiler to use:
CC         ?= gcc
# Extra options for catching bad stuff:
SANFLAGS   += -fsanitize=address,undefined
# Flags for warnings
WFLAGS     += -Wall -Wfatal-errors -Wno-unused-function -Wcast-align=strict -Wcast-qual -Wdangling-else -Wnull-dereference -Wold-style-declaration -Wold-style-definition -Wshadow -Wtype-limits -Wwrite-strings -Werror=bool-compare -Werror=bool-operation -Werror=int-to-pointer-cast -Werror=pointer-to-int-cast -Werror=return-type -Werror=uninitialized
# Flags for compiling individual files:
CFLAGS     += -g -O0 -std=c11 -pedantic-errors $(WFLAGS) $(SANFLAGS) -MMD -I src/ -I test/
# Flags for linking the final program:
LDFLAGS    += $(SANFLAGS)


## File configurations

# Programs we can build:
EXES       = unpack test-utilities
# Source files for executables
UNPACK_SOURCES = unpack.c unpack-utilities.c
TEST_SOURCES = test-utilities.c unpack-utilities.c

# Directories make searches for prerequisites and targets
VPATH      = src/ test/
# Output directory for build files
BUILDDIR   ?= _build/

# Figure out what files we need to make
UNPACK_OBJS = $(addprefix $(BUILDDIR), $(UNPACK_SOURCES:.c=.o))
UNPACK_DEPS = $(addprefix $(BUILDDIR), $(UNPACK_SOURCES:.c=.d))
TEST_OBJS = $(addprefix $(BUILDDIR), $(TEST_SOURCES:.c=.o))
TEST_DEPS = $(addprefix $(BUILDDIR), $(TEST_SOURCES:.c=.d))


## Rules

# First rule is the default
# Builds both programs but doesn’t run anything.
all: $(EXES)

# Make build directory
$(BUILDDIR):
	$(TRACE_DIR)
	$(Q)mkdir -p $@

# How to build the unpack program
unpack: $(UNPACK_OBJS)
	$(TRACE_LD)
	$(Q)$(CC) $(LDFLAGS) $^ -o $@

# How to build the test program
test-utilities: $(TEST_OBJS)
	$(TRACE_LD)
	$(Q)$(CC) $(LDFLAGS) $^ -o $@

# How to compile one .c file into a .o file
$(BUILDDIR)%.o: %.c | $(BUILDDIR)
	$(TRACE_CC)
	$(Q)$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Removes all the build products
clean:
	$(Q)rm -rf $(BUILDDIR)
	$(Q)rm -f  $(EXES)

# Gradescope submission for CS213
submit:
	$(Q)~cs213/HANDOUT/submit213 submit --hw packlab unpack-utilities.c


# Targets that are not actually files we can build:
.PHONY: all clean submit

# Dependencies
# Include dependency rules for picking up header changes (by convention at bottom of makefile)
-include $(UNPACK_DEPS)
