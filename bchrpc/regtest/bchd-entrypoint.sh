#!/bin/bash

if [ "$1" == "bchd1" ];
then
    bchd --slpcachemaxsize=1 --connect=bchd2 --grpclisten=0.0.0.0 --rpccert=/data/rpc.bchd1.cert --rpckey=/data/rpc.bchd1.key -C /data/bchd.conf
fi

if [ "$1" == "bchd2" ];
then
    bchd --slpcachemaxsize=1 --notls -C /data/bchd.conf
fi
