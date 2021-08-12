#!/bin/bash


git clone https://github.com/torvalds/linux.git -b v$1  --single-branch --depth 1
cd linux
make headers_install -j8 ARCH=x86_64 INSTALL_HDR_PATH=/usr

