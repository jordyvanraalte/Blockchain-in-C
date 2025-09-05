# Compiler definitions
CC := gcc
CFLAGS := -Wall -Wextra -g
LDFLAGS := -lcrypto -luuid
OPENSSL_LIBS := -lcrypto
CUNIT_LIBS = -lcunit
MAIN_SRC := src/main.c

# Directories and target
TARGET_EXEC := blockchain
BUILD_DIR := build
SRC_DIRS := src
TEST_DIR := tests
INC_DIR := include
TARGET_TESTS := $(BUILD_DIR)/tests/test_runner

# Source files (both C and C++)
SRCS := $(shell find $(SRC_DIRS) -name '*.c')
TEST_FILES := $(shell find $(TEST_DIR) -name '*.c')

# Object files under build/
SRCS_NO_DOT := $(patsubst ./%,%,$(SRCS))
SRC_OBJS := $(SRCS_NO_DOT:%=$(BUILD_DIR)/%.o)
TEST_OBJS := $(TEST_FILES:%=$(BUILD_DIR)/%.o)

# Dependency files for automatic make dependency tracking
DEPS := $(SRC_OBJS:.o=.d)

# Include directories for header search (added include/)
INC_DIRS := $(shell find $(SRC_DIRS) -type d) $(shell find $(TEST_DIR) -type d) $(INC_DIR)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

all: $(BUILD_DIR)/$(TARGET_EXEC) $(TARGET_TESTS)

# Final executable build step
$(BUILD_DIR)/$(TARGET_EXEC): $(SRC_OBJS)
	$(CC) $(SRC_OBJS) -o $@ $(LDFLAGS)

# Rule for building C source files
$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC_FLAGS) -c $< -o $@

# setup for test runner
SRC_NO_MAIN := $(filter-out $(MAIN_SRC), $(SRCS))
SRC_OBJS_NO_MAIN := $(SRC_NO_MAIN:%=$(BUILD_DIR)/%.o)

$(TARGET_TESTS): $(SRC_OBJS_NO_MAIN) $(TEST_OBJS)
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INC_FLAGS) -o $@ $^ $(OPENSSL_LIBS) $(CUNIT_LIBS) $(LDFLAGS)

# Run tests
test: $(TARGET_TESTS)
	./$(TARGET_TESTS)

clean:
	rm -rf $(BUILD_DIR)

# Include dependency files (silencing errors if they don't exist yet)
-include $(DEPS)
