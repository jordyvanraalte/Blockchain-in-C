# Compiler definitions
CC := gcc
CXX := g++
CFLAGS := -Wall -Wextra -g
CXXFLAGS := -Wall -Wextra -g
LDFLAGS := -lcrypto

# Directories and target
TARGET_EXEC := blockchain
BUILD_DIR := build
SRC_DIRS := src

# Source files (both C and C++)
SRCS := $(shell find $(SRC_DIRS) -name '*.c' -or -name '*.cpp' -or -name '*.s')

# Object files under build/
# Remove leading ./ from SRC paths for cleaner build paths
SRCS_NO_DOT := $(patsubst ./%,%,$(SRCS))
OBJS := $(SRCS_NO_DOT:%=$(BUILD_DIR)/%.o)

# Dependency files for automatic make dependency tracking
DEPS := $(OBJS:.o=.d)

# Include directories for header search
INC_DIRS := $(shell find $(SRC_DIRS) -type d)
INC_FLAGS := $(addprefix -I,$(INC_DIRS))

# Compile flags including dependency generation
CPPFLAGS := $(INC_FLAGS) -MMD -MP

# Final executable build step
$(BUILD_DIR)/$(TARGET_EXEC): $(OBJS)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS)

# Rule for building C source files
$(BUILD_DIR)/%.c.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# Rule for building C++ source files
$(BUILD_DIR)/%.cpp.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

# Include dependency files (silencing errors if they don't exist yet)
-include $(DEPS)
