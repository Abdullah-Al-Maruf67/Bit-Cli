CC = gcc
CFLAGS = -Wall -Wextra -std=gnu99 -O2 -D_GNU_SOURCE
LIBS = -lcurl -lz -ljson-c -lssl -lcrypto
TARGET = bit
SOURCE = Bit.c

# Default target
all: $(TARGET)

# Compile the binary
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

# Install to system (optional)
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

# Clean build files
clean:
	rm -f $(TARGET)

# Run tests
test: $(TARGET)
	./$(TARGET) help

# Development with debug symbols
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Show help
help:
	@echo "Available targets:"
	@echo "  all     - Build the bit CLI (default)"
	@echo "  install - Install to /usr/local/bin/"
	@echo "  clean   - Remove build files"
	@echo "  test    - Run basic test"
	@echo "  debug   - Build with debug symbols"
	@echo "  help    - Show this help"

.PHONY: all install clean test debug help 