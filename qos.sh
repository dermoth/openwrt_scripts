#!/bin/ash

# Traffic shaping
#
# This is the base schema for traffic shaping:
#
#                                         +-----------+
#                                         | RootClass |
#                      +------------------+    1.1    +-----------------+
#                      |                  | 800 Kbits |                 |
#                      v                  +-----------+                 v
#                +-----------+                                    +-----------+
#                | LAN Class |                                    | LOC Class |
#       +--------+   1.10    +--------+                  +--------+   1.20    +--------+
#       |        |  50% LS   |        |                  |        |  50% LS   |        |
#       |        +-----+-----+        |                  |        +-----+-----+        |
#       |              |              |                  |              |              |
#       v              v              v                  v              v              v
# +-----------+  +-----------+  +-----------+      +-----------+  +-----------+  +-----------+
# | LowLat Cl.|  | Normal Cl.|  |  Bulk Cl. |      | LowLat Cl.|  | Normal Cl.|  |  Bulk Cl. |
# |    1.11   |  |    1.12   |  |    1.13   |      |    1.21   |  |    1.22   |  |    1.23   |
# |   40% LS  |  |   40% LS  |  |   20% LS  |      |   40% LS  |  |   40% LS  |  |   20% LS  |
# +-----------+  +-----------+  +-----------+      +-----------+  +-----------+  +-----------+
#
# That is 50% share between each user (LAN, LOC), then proportional
# distribution for Low Latency, Normal and Bulk traffic.
#
# 1. Users
#
# User traffic is marked by iptables before source address is masqueraded:
#  1:1x => LAN Traffic
#  1:2x => LOC Traffic
#
# 2. Leaf Classes
#
# Leaf Classes are defined as such:
#  Low Lat (1:x1): DNS, HTTP, SSH, IPSEC - Guaranteed minimum latency
#   Normal (1:x2): Anyhthing not Bulk
#     Bulk (1:x3): Known P2P Ports/Traffic
#

## Config

# Executables
cmd_iptables="/usr/sbin/iptables"
cmd_tc="/usr/sbin/tc"

# Set your outgoing interface and upload rate (in kbit/s) here
DEV=pppoe-wan
RATEUP=780 # Allow for PPPoE ovehead
RATEUS=490 # Rate per user - RATEUP/2
RATE40=196 # 40% of user's bw
RATE20=98 # 20% of user's bw

# Guaranteed latency for RATE40 LowLat class
LAT_MS=50 # At 780kbps, 196kbits takes 200ms - bring down to 50ms
          # (Minimum considering the RATEUP max rate)

# User classes source interfaces
LAN_USER=br-lan
LOC_USER=br-loc

# Port spec (TCP/UDP): {t|u}:{s|d}:<n>
#
# t = TCP
# u = UDP
#
# s = Source port
# d = Dest port
#
# n = Port number
#

# Low Lat UDP, TCP Ports ## TODO: test exception
LOWT="t:d:22 t:d:53 t:d:80 t:d:443 u:d:53 u:d:123"

# Bulk UDP, TCP Ports
#
# eMule: 4662, 4672
# Vuze: 19403, 19404, 35575, 16680, 33189, 1900
# Bitcoin: 8332, 8333
#
BULK="t:s:4662 u:s:4672 t:s:19403 u:s:19403 t:s:19404 t:s:8332 t:d:8332 t:s:8333 t:d:8333"

# NB: Also look near end of script for custom rules

## End

## DEBUG

# Uncomment these to debug commands
iptables="dbg_iptables"
tc="dbg_tc"

## End

# Debug functions - echo + run
dbg_iptables() {
	$cmd_iptables $@ ||
	echo E: iptables $@
}

dbg_tc() {
	$cmd_tc $@ ||
	echo E: tc $@
}

# Default commands
iptables=${iptables:-$cmd_iptables}
tc=${tc:-$cmd_tc}

# Reset everything to a known state (cleared)
$tc qdisc del dev $DEV root 2>/dev/null
# Flush and delete tables
$iptables -t mangle -D PREROUTING ! -i $DEV -j QoS_wan 2>/dev/null
$iptables -t mangle -D OUTPUT -j QoS_wan 2>/dev/null
$iptables -t mangle -F QoS_wan 2>/dev/null
$iptables -t mangle -X QoS_wan 2>/dev/null

# Stop here if given a stop command
if [ x"$1" == x"stop" ]
then
	echo QoS Stopped.
	exit 0
fi

# Add HFSC root qdisc
# FIXME: Remove default
$tc qdisc add dev $DEV root handle 1: hfsc

# Add main rate limit class
$tc class add dev $DEV parent 1: classid 1:1 hfsc sc rate ${RATEUP}kbit ul rate ${RATEUP}kbit

# Add per user classes
$tc class add dev $DEV parent 1:1 classid 1:10 hfsc ls m2 ${RATEUS}kbit
$tc class add dev $DEV parent 1:1 classid 1:20 hfsc ls m2 ${RATEUS}kbit

# Add leaf classes

# Low Lat
$tc class add dev $DEV parent 1:10 classid 1:11 hfsc sc umax 1500b dmax $LAT_MS rate ${RATE40}kbit
$tc class add dev $DEV parent 1:20 classid 1:21 hfsc sc umax 1500b dmax $LAT_MS rate ${RATE40}kbit

# Normal
$tc class add dev $DEV parent 1:10 classid 1:12 hfsc sc rate ${RATE40}kbit
$tc class add dev $DEV parent 1:20 classid 1:22 hfsc sc rate ${RATE40}kbit

# Bulk
$tc class add dev $DEV parent 1:10 classid 1:13 hfsc sc rate ${RATE20}kbit
$tc class add dev $DEV parent 1:20 classid 1:23 hfsc sc rate ${RATE20}kbit

# iptables QoS chain
$iptables -t mangle -N QoS_wan
$iptables -t mangle -A PREROUTING ! -i $DEV -j QoS_wan
$iptables -t mangle -A OUTPUT -j QoS_wan

# iptables MARK's - packet source (LAN/LOC)
# Default LAN (mark 1), unless from br-loc (mark 2)
$iptables -t mangle -A QoS_wan ! -i br-loc -j MARK --set-mark 0x0001
$iptables -t mangle -A QoS_wan -i br-loc -j MARK --set-mark 0x0002

# $tc filtering
#
# Tables:
#
# 800:0 :: Main filters - Distributes traffic into other tables
#
# ## x below is one of: 1=LAN, 2=LOC
#
# x0:0 :: IP filters
# x1:0 :: IP6 filters (from 6to4 de-capsulation)
#
# x01:0 :: TCP filters
# x02:0 :: UDP filters
# x03:0 :: Other filters
#
# NB: As much as I'd like to offer source filters (i.e. classify flow based
# on source), it's not gonna happen with NAT as filtering happens after the
# source is replaced. We could use MARK with masks to also identify other
# priorities.
#
# FIXME: IPv6 offsets not working right, and even if they did we can't
#        easily match IPv6 header lenght incl. options.

# 1. Functions

# This function takes a port spec and make a match out of it
# prototype: pspec2filter <dev> <mark> <pspec> <flowid>
# NB: <flowid> is only the last digit

pspec2filter() {
	dv=$1
	mk=$2
	arg=$3
	fi=$4

	p="${arg%%:*}"    # proto symbol (tcp/udp)
	arg="${arg#*:}"   # Unused part of pspec
	w="${arg%:*}"     # way symbol (source/dest)
	port="${arg#*:}"  # port number

	case "$p" in
	t)
		proto="tcp"
		pnum=1
		;;
	u)
		proto="udp"
		pnum=2
		;;
	*)
		echo "Invalid port specification: $arg ($p)"
		exec "$0" stop
	esac

	case "$w" in
	s)
		way="src"
		;;
	d)
		way="dst"
		;;
	*)
		echo "Invalid port specification: $arg ($w)"
		exec "$0" stop
	esac

	$tc filter add dev $dv parent 1:0 prio 1 u32 ht ${mk}0${pnum}:0: match $proto $way "$port" ffff flowid 1:${mk}${fi}
}

# 2. Tables
for mark in 1 2
do
	# Level 1
	#$tc filter add dev $DEV parent 1:0 prio 1 handle ${mark}0: u32 divisor 256
	#$tc filter add dev $DEV parent 1:0 prio 1 handle ${mark}1: u32 divisor 1

	# Level 2
	$tc filter add dev $DEV parent 1:0 prio 1 handle ${mark}01: u32 divisor 1
	$tc filter add dev $DEV parent 1:0 prio 1 handle ${mark}02: u32 divisor 1
	$tc filter add dev $DEV parent 1:0 prio 1 handle ${mark}03: u32 divisor 1
done

# 3. Protocol filters
for mark in 1 2
do
	# Can be used for dest ip classification
        #$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff link ${mark}0:0:

	# TCP
	$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff match ip protocol 0x06 0xff link ${mark}01:0: offset at 0 mask 0f00 shift 6 plus 0 eat
	#### TCP from de-capsulated ipv6
	###$tc filter add dev $DEV parent 1:0 prio 1 u32 ht ${mark}1:0: match ip6 protocol 0x06 0xff link ${mark}01:0: offset plus 320 eat

	# UDP
	#$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff match ip protocol 0x11 0xff link ${mark}02:0: offset at 0 mask 0f00 shift 6 plus 0 eat
	#### UDP from de-capsulated ipv6
	###$tc filter add dev $DEV parent 1:0 prio 1 u32 ht ${mark}1:0: match ip6 protocol 0x11 0xff link ${mark}02:0: offset at 0 mask 0 shift 0 plus 320 eat

	# ICMP and IGMP should have no issue in LowLat class as long as users don't flood themselves
	#$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff match ip protocol 0x01 0xff flowid 1:${mark}1
	#$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff match ip protocol 0x02 0xff flowid 1:${mark}1
	#### ICMPv6
	###$tc filter add dev $DEV parent 1:0 prio 1 u32 ht ${mark}1:0: match ip6 protocol 0x3a 0xff flowid 1:${mark}1

	#### 6to4 -- ipv6 encapsulated in ipv4 as proto 41
	###$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff match ip protocol 0x29 0xff link ${mark}1:0: offset at 0 mask 0f00 shift 6 plus 0 eat
	#### Get other protocols straight from ipv4+ipv6 headers
	###$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff match ip protocol 0x29 0xff link ${mark}03:0: offset at 0 mask 0f00 shift 6 plus 320 eat

	# All other protos
	$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff link ${mark}03:0: offset at 0 mask 0f00 shift 6 plus 0 eat

done

# 4. Low Lat & bulk
for mark in 1 2
do
	for pspec in $LOWT
	do
		pspec2filter $DEV $mark "$pspec" 1
	done

	for pspec in $BULK
	do
		pspec2filter $DEV $mark "$pspec" 3
	done

done

# 5. Normal (Everything else)
for mark in 1 2
do
	# NB: We append to the master table - anything unmatched in the
	# user tables will fall here.
	$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff flowid 1:${mark}2
done

## Custom rules
#
# Rules here should specify a filter number lower than 800 (ex 101:0:<n>
# where n < 800 for the LAN TCP bucket)

## End

echo QoS Started.

