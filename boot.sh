#! /bin/sh
autoreconf --install --force
BOOT_SHA=`git rev-parse --short HEAD 2>/dev/null`
if [ ! -z $BOOT_SHA ]; then
    echo $BOOT_SHA > boot_git_sha.txt
fi
