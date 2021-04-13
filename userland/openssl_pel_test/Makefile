CC=gcc
CFLAGS+=-Og -Wall -Wextra -ggdb3 -fsanitize=address -fPIC
INCLUDES+=-I../include
RM=rm -rf
BUILD_DIR?=$(PWD)/output
DEP_SRC=../crypto/aes.c ../crypto/sha1.c ../transport/pel.c
ORIG_DEP_SRC=../crypto/aes.c ../crypto/sha1.c ../transport/pel_orig.c

# Rules

all: openssl_client openssl_server pel_client pel_server select_client select_server pelorig_client pelorig_server

# Those binaries will stay in the victim machine

openssl_client: build_dir
	@ echo "  CC      $(BUILD_DIR)/openssl_client"
	@ $(CC) openssl_client.c $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) $(DEP_SRC) -o $(BUILD_DIR)/openssl_client -lssl -lcrypto

openssl_server: build_dir
	@ echo "  CC      $(BUILD_DIR)/openssl_server"
	@ $(CC) openssl_server.c $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) $(DEP_SRC) -o $(BUILD_DIR)/openssl_server -lssl -lcrypto

pel_client: build_dir
	@ echo "  CC      $(BUILD_DIR)/pel_client"
	@ $(CC) pel_client.c $(DEP_SRC) $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) -o $(BUILD_DIR)/pel_client -lssl -lcrypto

pel_server: build_dir
	@ echo "  CC      $(BUILD_DIR)/pel_server "
	@ $(CC) pel_server.c $(DEP_SRC) $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) -o $(BUILD_DIR)/pel_server -lssl -lcrypto

select_client: build_dir
	@ echo "  CC      $(BUILD_DIR)/select_client"
	@ $(CC) select_client.c $(DEP_SRC) $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) -o $(BUILD_DIR)/select_client -lssl -lcrypto

select_server: build_dir
	@ echo "  CC      $(BUILD_DIR)/select_server "
	@ $(CC) select_server.c $(DEP_SRC) $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) -o $(BUILD_DIR)/select_server -lssl -lcrypto

pelorig_client: build_dir
	@ echo "  CC      $(BUILD_DIR)/pelorig_client"
	@ $(CC) pelorig_client.c $(ORIG_DEP_SRC) $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) -o $(BUILD_DIR)/pelorig_client -lssl -lcrypto

pelorig_server: build_dir
	@ echo "  CC      $(BUILD_DIR)/pelorig_server "
	@ $(CC) pelorig_server.c $(ORIG_DEP_SRC) $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) -o $(BUILD_DIR)/pelorig_server -lssl -lcrypto


.PHONY : clean

build_dir:
	@ mkdir -p $(BUILD_DIR)

clean:
	@ $(RM) $(BUILD_DIR)
