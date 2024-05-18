#!/bin/bash

if [ $# -eq 0 ] ; then
    echo "No arguments"
    exit 1
fi

n=$1
let flows=128/n
for ((i = 1 ; i <= n ; i++)) ; do
    m server$i python /mininet/server.py server$i $flows &
done
