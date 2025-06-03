#!/usr/bin/env bash
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

#
# Use BGP+EVPN for VXLAN with CloudStack instead of Multicast
#
# The default 'modifyvxlan.sh' script from CloudStack uses Multicast instead of EVPN for VXLAN
# In order to use this script and thus utilize BGP+EVPN, symlink this file:
#
# cd /usr/share
# ln -s cloudstack-common/scripts/vm/network/vnet/modifyvxlan-evpn.sh modifyvxlan.sh
#
#
# CloudStack will not handle the BGP configuration nor communication, the operator of the hypervisor will
# need to configure the properly.
#
# Frrouting is recommend to be used on the hypervisor to establish BGP sessions with upstream routers and
# exchange BGP+EVPN information.
#
# More information about BGP and EVPN with FRR: https://vincent.bernat.ch/en/blog/2017-vxlan-bgp-evpn
#

DSTPORT=4789
#SVDtunnelDev=""

# We bind our VXLAN tunnel IP(v4) on Loopback device 'lo'
DEV="lo"

usage() {
    echo "Usage: $0: -o <op>(add | delete) -v <vxlan id> -p <pif> -b <bridge name> (-6) -d <delete bridge>(true|false)"
}

localAddr() {
    local FAMILY=$1

    if [[ -z "$FAMILY" || $FAMILY == "inet" ]]; then
       ip -4 -o addr show scope global dev ${DEV} | awk 'NR==1 {gsub("/[0-9]+", "") ; print $4}'
    fi

    if [[ "$FAMILY" == "inet6" ]]; then
       ip -6 -o addr show scope global dev ${DEV} | awk 'NR==1 {gsub("/[0-9]+", "") ; print $4}'
    fi
}

addVxlanSVD() {
    local VNI=$1
    local PIF=$2
    local VLAN_BR=$3
    local FAMILY=$4
    local VXLAN_DEV=$SVDtunnelDev
    local VETHPEER="$(ip link show type veth dev $PIF | grep -o -P '(?<=@).*(?=:)')"
    local VlanAwareBR="$(readlink /sys/class/net/$VETHPEER/master | sed 's#../##')"

    echo "vlan aware bridge is $VlanAwareBR"

    if [[ $VNI !=  $(bridge vlan show dev ${VETHPEER} | grep -o "${VNI}$") ]]; then
        bridge vlan add vid ${VNI} dev ${VlanAwareBR} self
        if [ $? -gt 0 ]; then 
            echo "command \"bridge vlan add vid ${VNI} dev ${VlanAwareBR} self\" failed"
            return 1
	fi
        bridge vlan add vid ${VNI} dev ${VETHPEER}
        if [ $? -gt 0 ]; then 
            echo "command \"bridge vlan add vid ${VNI} dev ${VETHPEER}\" failed"
            return 1
	fi
        bridge vlan add vid ${VNI} dev ${VXLAN_DEV}
        if [ $? -gt 0 ]; then 
            echo "command \"bridge vlan add vid ${VNI} dev ${VXLAN_DEV}\" failed"
            return 1
	fi
        bridge vlan add vid ${VNI} tunnel_info id ${VNI} dev ${VXLAN_DEV}
        if [ $? -gt 0 ]; then 
            echo "command \"bridge vlan add vid ${VNI} tunnel_info id ${VNI} dev ${VXLAN_DEV}\" failed"
            return 1
	fi
    fi
    return 0
}
 

addVlan() {
    local vlanId=$1
    local pif=$2
    local vlanDev=$pif.$vlanId
    local vlanBr=$3

    if [ ! -d /sys/class/net/$vlanDev ]
    then
        ip link add link $pif name $vlanDev type vlan id $vlanId > /dev/null
        echo 1 > /proc/sys/net/ipv6/conf/$vlanDev/disable_ipv6
        ip link set $vlanDev up

        if [ $? -gt 0 ]
        then
            # race condition that someone already creates the vlan
            if [ ! -d /sys/class/net/$vlanDev ]
            then
                printf "Failed to create vlan $vlanId on pif: $pif."
                return 1
            fi
        fi
    fi

    # disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/$vlanDev/disable_ipv6
    # is up?
    ip link set $vlanDev up > /dev/null 2>/dev/null

    if [ ! -d /sys/class/net/$vlanBr ]
    then
        ip link add name $vlanBr type bridge
        echo 1 > /proc/sys/net/ipv6/conf/$vlanBr/disable_ipv6
        ip link set $vlanBr up

        if [ $? -gt 0 ]
        then
            if [ ! -d /sys/class/net/$vlanBr ]
            then
               printf "Failed to create br: $vlanBr"
               return 2
            fi
        fi
    fi

    #pif is eslaved into vlanBr?
    ls /sys/class/net/$vlanBr/brif/ |grep -w "$vlanDev" > /dev/null
    if [ $? -gt 0 ]
    then
        ip link set $vlanDev master $vlanBr
        if [ $? -gt 0 ]
        then
            ls /sys/class/net/$vlanBr/brif/ |grep -w "$vlanDev" > /dev/null
            if [ $? -gt 0 ]
            then
                printf "Failed to add vlan: $vlanDev to $vlanBr"
                return 3
            fi
        fi
    fi
    # disable IPv6
    echo 1 > /proc/sys/net/ipv6/conf/$vlanBr/disable_ipv6
    # is vlanBr up?
    ip link set $vlanBr up > /dev/null 2>/dev/null

    return 0
}


addVxlan() {
    local VNI=$1
    local PIF=$2
    local VXLAN_BR=$3
    local FAMILY=$4
    local VXLAN_DEV=vxlan${VNI}
    local ADDR=$(localAddr ${FAMILY})

    echo "local addr for VNI ${VNI} is ${ADDR}"

    if [[ ! -d /sys/class/net/${VXLAN_DEV} ]]; then
        ip -f ${FAMILY} link add ${VXLAN_DEV} type vxlan id ${VNI} local ${ADDR} dstport ${DSTPORT} nolearning
        ip link set ${VXLAN_DEV} up
        sysctl -qw net.ipv6.conf.${VXLAN_DEV}.disable_ipv6=1
    fi

    if [[ ! -d /sys/class/net/$VXLAN_BR ]]; then
        ip link add name ${VXLAN_BR} type bridge
        ip link set ${VXLAN_BR} up
        sysctl -qw net.ipv6.conf.${VXLAN_BR}.disable_ipv6=1
    fi

    bridge link show|grep ${VXLAN_BR}|awk '{print $2}'|grep "^${VXLAN_DEV}\$" > /dev/null
    if [[ $? -gt 0 ]]; then
        ip link set ${VXLAN_DEV} master ${VXLAN_BR}
    fi

    if [[ ! -d /sys/class/net/$VXLAN_BR ]]; then
        ip link add name ${VXLAN_BR} type bridge
        ip link set ${VXLAN_BR} up
        sysctl -qw net.ipv6.conf.${VXLAN_BR}.disable_ipv6=1
    fi

    bridge link show|grep ${VXLAN_BR}|awk '{print $2}'|grep "^${VXLAN_DEV}\$" > /dev/null
    if [[ $? -gt 0 ]]; then
        ip link set ${VXLAN_DEV} master ${VXLAN_BR}
    fi
}

deleteVxlanSVD() {
    local VNI=$1
    local PIF=$2
    local FAMILY=$4
    local VXLAN_DEV=$SVDtunnelDev
    local VETHPEER="$(ip link show type veth dev $PIF | grep -o -P '(?<=@).*(?=:)')"
    local VlanAwareBR="$(readlink /sys/class/net/$VETHPEER/master | sed 's#../##')"

    echo "vlan aware bridge is $VlanAwareBR"

    bridge vlan del vid ${VNI} dev ${VlanAwareBR} self
    bridge vlan del vid ${VNI} dev ${VXLAN_DEV} 
    bridge vlan del vid ${VNI} dev ${VXLAN_DEV} tunnel_info id ${VNI}
    bridge vlan del vid ${VNI} dev ${VETHPEER}

}

deleteVlan() {
    local vlanId=$1
    local pif=$2
    local vlanDev=$pif.$vlanId
    local vlanBr=$3
    local deleteBr=$4

    if [ "$deleteBr" == "true" ]
    then
        ip link delete $vlanDev type vlan > /dev/null

        if [ $? -gt 0 ]
        then
            printf "Failed to del vlan: $vlanId"
            return 1
        fi
        ip link set $vlanBr down

        if [ $? -gt 0 ]
        then
            return 1
        fi

        ip link delete $vlanBr type bridge

        if [ $? -gt 0 ]
        then
            printf "Failed to del bridge $vlanBr"
            return 1
        fi
    fi
    return 0
}

deleteVxlan() {
    local VNI=$1
    local PIF=$2
    local VXLAN_BR=$3
    local FAMILY=$4
    local VXLAN_DEV=vxlan${VNI}

    ip link set ${VXLAN_DEV} nomaster
    ip link delete ${VXLAN_DEV}

    ip link set ${VXLAN_BR} down
    ip link delete ${VXLAN_BR} type bridge
}

OP=
VNI=
FAMILY=inet
option=$@

while getopts 'o:v:p:b:d:6' OPTION
do
  case $OPTION in
  o)    oflag=1
        OP="$OPTARG"
        ;;
  v)    vflag=1
        VNI="$OPTARG"
        ;;
  p)    pflag=1
        PIF="$OPTARG"
        ;;
  b)    bflag=1
        BRNAME="$OPTARG"
        ;;
  d)    dflag=1
        deleteBr="$OPTARG"
        ;;
  6)
        FAMILY=inet6
        ;;
  ?)    usage
        exit 2
        ;;
  esac
done

if [[ "$oflag$vflag$pflag$bflag" != "1111" ]]; then
    usage
    exit 2
fi

lsmod|grep ^vxlan >& /dev/null
if [[ $? -gt 0 ]]; then
    modprobe=`modprobe vxlan 2>&1`
    if [[ $? -gt 0 ]]; then
        echo "Failed to load vxlan kernel module: $modprobe"
        exit 1
    fi
fi

SVDtunnelDev=$(ip -d link show type vxlan | awk '
               /^[0-9]+: / { iface = $2; sub(":", "", iface); } 
	       /vlan_tunnel on/ { print iface; } ') 

tundevMaster=$(ip link show dev $SVDtunnelDev type vxlan | awk '
               /master/ {for(i=1;i<=NF;i++) if($i=="master") print $(i+1)}')

if [[ $SVDtunnelDev != "" ]]; then
        echo "Info: Found Single VXLAN Device (SVD) setup (vlan_tunnel attr turned on)"
	if [[ $(ip -d link show dev $tundevMaster | awk '/vlan_filtering 1/') == "" ]]; then
            echo "Found a vxlan interface for SVD topology but master bridge: $tundevMaster, does not have vlan_filtering enabled"
            exit 1
	fi
fi


echo "VXLAN dev: $SVDtunnelDev"

#
# Add a lockfile to prevent this script from running twice on the same host
# this can cause a race condition
#

LOCKFILE=/var/run/cloud/vxlan.lock

(
    flock -x -w 10 200 || exit 1
    if [[ "$OP" == "add" ]]; then
	    if [[ $SVDtunnelDev != "" ]]; then
	        addVxlanSVD ${VNI} ${PIF} ${BRNAME} ${FAMILY} 
                if [[ $? -gt 0 ]]; then
                    exit 1
                fi
                addVlan ${VNI} ${PIF} ${BRNAME}
	    else
        	addVxlan ${VNI} ${PIF} ${BRNAME} ${FAMILY}
	    fi

        if [[ $? -gt 0 ]]; then
            exit 1
        fi
    elif [[ "$OP" == "delete" ]]; then
        if [[ $SVDtunnelDev != "" ]]; then
            deleteVlan ${VNI} ${PIF} ${BRNAME} ${deleteBr}
            if [[ $? -gt 0 ]]; then
                exit 1
            fi
            deleteVxlanSVD ${VNI} ${PIF} ${BRNAME} ${FAMILY} 
        else
            deleteVxlan ${VNI} ${PIF} ${BRNAME} ${FAMILY}
        fi
    fi
) 200>${LOCKFILE}
