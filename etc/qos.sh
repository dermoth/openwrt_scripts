#!/bin/ash

# Traffic shaping
#
# This is the base schema for traffic shaping:
#
#                                            +-----------+
#                                            | RootClass |
#                +---------------------------+    1.1    +----------------+
#                |                           | 800 Kbits |                |
#                |                           +-----------+                |
#                |                                 |                      |
#                v                                 v                      v
#          +-----------+                     +-----------+           +---------+
#          | LAN Class |                     | LOC Class |           |  VoIP   |
#     +----+   1.10    +----+           +----+   1.20    +----+      |  1.30   |
#     |    |  50% LS   |    |           |    |  50% LS   |    |      | 200k LS |
#     |    +-----+-----+    |           |    +-----+-----+    |      +---------+
#     |          |          |           |          |          |           |
#     v          v          v           v          v          v           v
# +--------+ +--------+ +--------+  +--------+ +--------+ +--------+ +---------+
# | LowLat | | Normal | |  Bulk  |  | LowLat | | Normal | |  Bulk  | |  VoIP   |
# |  1.11  | |  1.12  | |  1.13  |  |  1.21  | |  1.22  | |  1.23  | |  1.31   |
# | 40% LS | | 40% LS | | 20% LS |  | 40% LS | | 40% LS | | 20% LS | | 100% LS |
# +--------+ +--------+ +--------+  +--------+ +--------+ +--------+ +---------+
#
# That is 50% share between each user (LAN, LOC), aftter removing the 200k
# reserved VoIP bandwidth then proportional distribution for Low Latency,
# Normal and Bulk traffic.
#
# 1. Users/VoIP
#
# User traffic is marked by iptables before source address is masqueraded:
#  1:1x => LAN Traffic
#  1:2x => LOC Traffic
#
# VoIP traffic comes from a static IP address (the ATA)
#  1.30 => VoIP Traffic
#
# 2. Leaf Classes
#
# Leaf Classes are defined as such:
#  Low Lat (1:x1): DNS, HTTP, SSH, IPSEC - Guaranteed minimum latency
#   Normal (1:x2): Anyhthing not Bulk
#     Bulk (1:x3): Known P2P Ports/Traffic
#
#  VoIP (1.31): Tuned for the specific RTP packet size used

## Config

# Executables
cmd_iptables="/usr/sbin/iptables"
cmd_tc="/usr/sbin/tc"

# Set your outgoing interface and upload rate (in kbit/s) here
DEV=pppoe-wan
RATEUP=10000 # Allow for PPPoE ovehead
RATEVO=500 # Reserved for VoIP
RATEUS=4750 # Rate per user - (RATEUP - RATEVO)/2
RATE40=1900 # 40% of user's bw
RATE20=950  # 20% of user's bw

# Guaranteed latency for VoIP, assuming 3*200 bytes packets
# + overhead = 3*225 - these packets can be transfered in 0.78ms
LAT_VO=1
PS_BR=675
# RTP packet size for VoIP (counting overhead)
PS_VO=225

# iptables rule to match Voip traffic
# ATA is .10, but also allow other devices... .8  to .15
MATCH_VO="-s 192.168.1.8/29 -p udp"

# Guaranteed latency for RATE40 LowLat class (assuming 1500 MTU)
LAT_MS=50 # At 780kbps, 196kbits takes 200ms - bring down to 50ms
          # (Minimum considering the RATEUP max rate)

# User classes source interfaces
LAN_USER=br-lan
LOC_USER=br-loc

# Max payload size for LOWLAT class. According to Google's SPDY research
# project whitepaper, typical header sizes of 700-800 bytes is common
# for HTTP. This bitmask lets us filter out all packets 1024 bytes and
# larger. This will still rule out bulk HTTP-based uploads.
LB_MAXMASK=0xfc00

# Port spec (TCP/UDP): {t|u}:{s|d}:<n>
#                        |     |    |
# t = TCP _______________|     |    |
# u = UDP                      |    |
#                              |    |
# s = Source port _____________|    |
# d = Dest port                     |
#                                   |
# n = Port number  _________________|
#     (TCP or UDP)

# Low Lat UDP, TCP Ports
LOWLAT="t:d:53 u:d:53 u:d:123"

# Low Lat UDP, TCP ports for service doing bulk transfers too, limited
# to LB_MAXMASK
LOWLAT_BULK="t:d:22 t:d:80 t:d:443 u:d:4500"

# Bulk UDP, TCP Ports
#
# eMule: 4662, 4672
# Vuze: 19403, 19404, 35575, 16680, 33189, 1900
# Bitcoin: 8332, 8333
#
BULK="t:s:4662 u:s:4672 t:s:19403 u:s:19403 t:s:19404 u:s:35575 u:s:16680 u:s:33189 u:s:1900 u:s:19404 t:s:8332 t:d:8332 t:s:8333 t:d:8333 u:s:35575"

# NB: Also look near end of script for custom rules

## End

## DEBUG

# Uncomment this to debug commands
#DEBUG=1

## End

# Debug functions - echo + run
dbg_iptables() {
	[ "${DEBUG:-0}" -eq 0 ] || echo D: iptables "$@"
	$cmd_iptables "$@" ||
	echo E: iptables "$@"
}

dbg_tc() {
	[ "${DEBUG:-0}" -eq 0 ] || echo D: tc "$@"
	$cmd_tc "$@" ||
	echo E: tc "$@"
}

# Default commands
iptables="dbg_iptables"
tc="dbg_tc"

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
$tc class add dev $DEV parent 1:1 classid 1:30 hfsc ls m2 ${RATEVO}kbit

# Add leaf classes

# VoIP
$tc class add dev $DEV parent 1:30 classid 1:31 hfsc sc umax ${PS_BR}b dmax $LAT_VO rate ${RATEVO}kbit

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

# Mark vor VoIP traffic
$iptables -t mangle -A QoS_wan $MATCH_VO -m length --length 0:$PS_VO -j MARK --set-mark 0x0003

# $tc filtering
#
# Tables:
#
# 800:0 :: Main filters - Distributes traffic into other tables
#
# ## x below is one of: 1=LAN, 2=LOC
#
# Level 1 Tables:
#  x0:0 :: IP filters
#  x1:0 :: IP6 filters (from 6to4 de-capsulation)
#
# Level 2 Tables:
#  x01:0 :: TCP filters
#  x02:0 :: UDP filters
#  x03:0 :: Other filters
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
# prototype: pspec2filter <dev> <mark> <pspec> <flowid> [<flag> [<flowid>]]
# NB: <flowid> is only the last digit

pspec2filter() {
	dv=$1
	mk=$2
	arg=$3
	fi=$4
	flag=${5:-} # If set, optional classification flag
	fb=${6:-} # if flag is set, this is the fallback flowid

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

	case "$flag" in
	nobulk)
		# Match only small IP packets, the rest goes to "fallback" flowid
		$tc filter add dev $dv parent 1:0 prio 1 u32 ht ${mk}0${pnum}:0: match u16 0x0000 "$LB_MAXMASK" at 2 \
		               match $proto $way "$port" 0xffff flowid 1:${mk}${fi}
		$tc filter add dev $dv parent 1:0 prio 1 u32 ht ${mk}0${pnum}:0: match $proto $way "$port" 0xffff flowid 1:${mk}${fb}
		;;
	*)
		$tc filter add dev $dv parent 1:0 prio 1 u32 ht ${mk}0${pnum}:0: match $proto $way "$port" 0xffff flowid 1:${mk}${fi}
	esac
}

# 2. Tables
for mark in 1 2
do
	## See Tables section above (comment) for details

	# Level 1 - IP/IP6 Traffic (unused)
	#$tc filter add dev $DEV parent 1:0 prio 1 handle ${mark}0: u32 divisor 256
	#$tc filter add dev $DEV parent 1:0 prio 1 handle ${mark}1: u32 divisor 1

	# Level 2 - TCP/UDP/Other traffic
	$tc filter add dev $DEV parent 1:0 prio 1 handle ${mark}01: u32 divisor 1
	$tc filter add dev $DEV parent 1:0 prio 1 handle ${mark}02: u32 divisor 1
	$tc filter add dev $DEV parent 1:0 prio 1 handle ${mark}03: u32 divisor 1
done

# 3. Protocol filters
for mark in 1 2
do
	## See Tables section above (comment) for details

	# Can be used for dest ip classification
	#$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff link ${mark}0:0:

	# TCP
	$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff match ip protocol 6 0xff link ${mark}01:0: offset at 0 mask 0x0f00 shift 6 plus 0 eat
	#### TCP from de-capsulated ipv6 (How can we match variable-length header?)
	###$tc filter add dev $DEV parent 1:0 prio 1 u32 ht ${mark}1:0: match ip6 protocol 0x06 0xff link ${mark}01:0: offset plus 320 eat

	# UDP
	$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x000${mark} 0xffff match ip protocol 17 0xff link ${mark}02:0: offset at 0 mask 0x0f00 shift 6 plus 0 eat
	#### UDP from de-capsulated ipv6 (How can we match variable-length header?)
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

# 4. VoIP
$tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x0003 0xffff flowid 1:31

# 5. Low Lat & bulk
for mark in 1 2
do
	for pspec in $LOWLAT
	do
		pspec2filter $DEV $mark "$pspec" 1
	done
	for pspec in $LOWLAT_BULK
	do
		pspec2filter $DEV $mark "$pspec" 1 nobulk 3
	done

	for pspec in $BULK
	do
		pspec2filter $DEV $mark "$pspec" 3
	done

done

# 6. Normal (Everything else)
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

