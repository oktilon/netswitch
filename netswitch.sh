#!/bin/bash

if [ "$EUID" -ne 0 ]
    then echo "Please run as root"
    exit 1
fi

logger "netswitch: started as $$"
lock=0
if [ -f /var/run/netswitch ]; then
    pid=$(cat /var/run/netswitch)
    if [ -n "$pid" ]; then
        lock=$(ps aux | grep netswitch | grep ${pid} | grep -v grep | wc -l)
    fi
    if [ "$lock" -gt "0" ]; then
        logger "netswitch: duplicate lock, stopped $$"
        exit 1
    fi
fi
echo "$$" > /var/run/netswitch

which curl &> /dev/null
if [ "$?" -ne "0" ]; then
    export DEBIAN_FRONTEND=noninteractive
    set -e
    apt -y install curl=7.74.0-1
fi

which /sbin/ifmetric &> /dev/null
if [ "$?" -ne "0" ]; then
    export DEBIAN_FRONTEND=noninteractive
    set -e
    apt -y install ifmetric/oldstable
fi

routes_cnt=`/sbin/route | grep default | grep UG | wc -l`

if [ "$routes_cnt" -gt "1" ]; then
    server=`cat /home/defigo/.config/Doorbell\ ink/Doorbell.conf | grep url= | awk -F = '{print $2}'`
    host=`cat /home/defigo/.config/Doorbell\ ink/Doorbell.conf | grep url= | awk -F = '{print $2}' | awk -F / '{print $3}'`
    base_domain=$(echo "$host" | awk -F . '{print $(NF-1)"\t"$NF}' | sed 's/\t/./g')
    host_ip=$(getent ahosts "$host" | awk '{print $1; exit}')
    use_if=`ip route get "$host_ip" | grep -Po '(?<=(dev ))(\S+)'`

    set +e
    valid=0
    json=$(curl --connect-timeout 2 -k -s $server 2> /dev/null)
    if [ "$?" -eq "0" ]; then
        valid=$(echo "$json" | grep field | grep request | wc -l)
    fi

    if [ "$valid" -eq "0" ]; then
        if [ "$use_if" = "wwan0" ]; then
            /sbin/ifmetric wwan0 710
            logger "netswitch: Use ethernet"
        else
            /sbin/ifmetric wwan0 10
            logger "netswitch: Use wireless"
        fi
    else
        if [ "$use_if" = "wwan0" ]; then
            cnt=$(ping -c 2 -I eth0 -W 2 -4 "$base_domain" 2> /dev/null | grep transmitted | awk '{print $4}')
            if [ "$cnt" -gt "1" ]; then
                /sbin/ifmetric wwan0 710
                logger "netswitch: Use ethernet"
                pid=$(pidof RtmpBroadcaster)
                if [ -n "$pid" ]; then
                    if [ "$pid" -gt "0" ]; then
                        kill -s SIGUSR1 $pid
                    else
                        logger "netswitch: RtmpBroadcaster not found"
                    fi
                else
                    logger "netswitch: RtmpBroadcaster not found"
                fi
            fi
        fi
    fi
fi

rm -rf /var/run/netswitch
logger "netswitch: stopped as $$"