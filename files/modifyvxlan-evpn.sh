#!/usr/bin/env bash
#
# Use BGP+EVPN for VXLAN with CloudStack instead of Multicast
#
# Place this file on all KVM hypervisors at /usr/share/modifyvxlan.sh
#
# More information about BGP and EVPN with FRR: https://vincent.bernat.ch/en/blog/2017-vxlan-bgp-evpn
#

DSTPORT=4789

# MTU for every VXLAN device and bridge this script manages. A bridge larger than
# its guests' MTU is harmless: a guest never sends more than its own MTU, so 1500
# guests are unaffected. 9150 lets guests that run VXLAN themselves keep a 9100-byte
# inner MTU (9100 plus one 50-byte wrap). Our own wrap adds 50 more, so the
# hypervisor's underlay has to carry 9200; with a 9216-byte fabric that leaves 16
# bytes of margin, which also means the VTEP must stay IPv4-sourced (an IPv6 outer
# header costs 20 more), so don't use -6 with this MTU.
MTU=9150

# We bind our VXLAN tunnel IP(v4) on Loopback device 'lo'
DEV="lo"

usage() {
    echo "Usage: $0: -o <op>(add | delete) -v <vxlan id> -p <pif> -b <bridge name> (-6)"
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

    # On every add, not only at creation, so a bridge made before this setting (or
    # by an older copy of this script) is raised too. The VXLAN port first, then the
    # bridge; libvirt gives each tap the bridge's MTU when it attaches it.
    ip link set ${VXLAN_DEV} mtu ${MTU}
    ip link set ${VXLAN_BR} mtu ${MTU}
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

while getopts 'o:v:p:b:6' OPTION
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


#
# Add a lockfile to prevent this script from running twice on the same host
# this can cause a race condition
#

LOCKFILE=/var/run/cloud/vxlan.lock

(
    flock -x -w 10 200 || exit 1
    if [[ "$OP" == "add" ]]; then
        addVxlan ${VNI} ${PIF} ${BRNAME} ${FAMILY}

        if [[ $? -gt 0 ]]; then
            exit 1
        fi
    elif [[ "$OP" == "delete" ]]; then
        deleteVxlan ${VNI} ${PIF} ${BRNAME} ${FAMILY}
    fi
) 200>${LOCKFILE}