#!/bin/bash

set -exo pipefail

PS3='Select Linux distro: '
options=("RHEL" "Debian" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "RHEL")
            echo "you chose choice 1"
            break
            ;;
        "Debian")
            echo "you chose choice 2"
            break
            ;;
        "Quit")
            break
            ;;
        *) echo "invalid option $REPLY";;
    esac
done


echo "Please input Docker tag:"
read docker_tag
echo "Please input kernel version":
read kernel_version


if [ $opt == "RHEL" ]; then
docker_file="dockerfile_rhel"
fi

docker image build . -t "reptile:${opt}" -f $docker_file --build-arg TAG=$docker_tag --build-arg KERNEL_VERSION=$kernel_version #--no-cache
container_id=$(docker create "reptile:$opt")
docker cp $id:/Reptile/payload_installer.sh - > .
docker rm -v $id
docker image rm "reptile:$opt"

