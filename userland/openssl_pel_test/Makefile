CC=gcc
CFLAGS+=-Og -Wall -Wextra -fsanitize=address,undefined
INCLUDES+=-I../include
RM=rm -rf
BUILD_DIR?=$(PWD)/output
DEP_SRC=../crypto/aes.c ../crypto/sha1.c ../transport/pel.c

# Rules

all: client server

# Those binaries will stay in the victim machine

client: build_dir
	@ echo "  CC      $(BUILD_DIR)/client"
	@ $(CC) client.c $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) $(DEP_SRC) -o $(BUILD_DIR)/client -lssl -lcrypto
	@ strip $(BUILD_DIR)/client

server: build_dir
	@ echo "  CC      $(BUILD_DIR)/server"
	@ $(CC) server.c $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) $(DEP_SRC) -o $(BUILD_DIR)/server -lssl -lcrypto
	@ strip $(BUILD_DIR)/server

.PHONY : clean

build_dir:
	@ mkdir -p $(BUILD_DIR)

clean:
	@ $(RM) $(BUILD_DIR)
