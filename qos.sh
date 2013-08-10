#!/bin/ash

# Traffic shaping
#
# This is the base schema for traffic shaping:
# 
#                                           +------------+
#                                           | Root Class |
#                       +-------------------+    1.1     +------------------+
#                       |                   |  80 Mbits  |                  |
#                       v                   +------------+                  v
#                 +------------+                                      +------------+
#                 |  LAN Class |                                      |  LOC Class |
#       +---------+    1.10    +--------+                   +---------+    1.20    +--------+
#       |         |   50% LS   |        |                   |         |   50% LS   |        |
#       |         +-----+------+        |                   |         +-----+------+        |
#       |               |               |                   |               |               |
#       v               v               v                   v               v               v
# +------------+  +------------+  +------------+      +------------+  +------------+  +------------+
# | Low Lat Cl.|  | Normal Cl. |  |  Bulk Cl.  |      | Low Lat Cl.|  | Normal Cl. |  |  Bulk Cl.  |
# |    1.11    |  |    1.12    |  |    1.13    |      |    1.21    |  |    1.22    |  |    1.23    |
# |   40% LS   |  |   40% LS   |  |   20% LS   |      |   40% LS   |  |   40% LS   |  |   20% LS   |
# +------------+  +------------+  +------------+      +------------+  +------------+  +------------+
#
# That is, 50% share between each user (LAN, LOC), then proportional
# distribution for Low Latency, Normal and Bulk traffic.
#
# 1. Users
#
# User traffic is marked by iptables before source address is masqueraded:
#  1: LAN Traffic
#  2: LOC Traffic
#
# 2. Leaf Classes
#
# Leaf Classes are defined as such:
#  Low Lat (1:x1): DNS, HTTP, SSH, IPSEC - Guaranteed minimum latency
#   Normal (1:x2): Anyhthing not Bulk
#     Bulk (1:x3): Known P2P Ports/Traffic
#

## Config

# Set your outgoing interface and upload rate (in kbit/s) here
DEV=pppoe-wan
RATEUP=780 # Allow for PPPoE ovehead
RATEUS=490 # Rate per user - RATEUP/2
RATE40=196 # 40% of user's bw
RATE20=98 # 20% of user's bw

# Guaranteed latency for RATE40 LowLat class
LAT_MS=50 # At 780kbps, 196kbits takes 200ms - bring down to 50ms

# User classes source interfaces
LAN_USER=br-lan
LOC_USER=br-loc

# Port spec: {s|d}:<n>
# s = Source port
# d = Dest port
# n = Port number

# Low Lat UDP, TCP Ports
LL_UDP="d:53 d:123"
LL_TCP="d:22 d:53 d:80 d:443"

# Bulk UDP, TCP Ports
BU_UDP="s:4672"
BU_TCP="s:4662"

## End

# Reset everything to a known state (cleared)
tc qdisc del dev $DEV root 2>/dev/null
# Flush and delete tables
iptables -t mangle -D PREROUTING ! -i $DEV -j QoS_wan 2>/dev/null
iptables -t mangle -D OUTPUT -j QoS_wan 2>/dev/null
iptables -t mangle -F QoS_wan 2>/dev/null
iptables -t mangle -X QoS_wan 2>/dev/null

# Stop here if given a stop command
if [ x"$1" == x"stop" ]
then
	echo QoS Stopped.
	exit 0
fi

# Add HFSC root qdisc
tc qdisc add dev $DEV root handle 1: hfsc

# Add main rate limit class
tc class add dev $DEV parent 1: classid 1:1 hfsc sc rate ${RATEUP}kbit ul rate ${RATEUP}kbit

# Add per user classes
tc class add dev $DEV parent 1:1 classid 1:10 hfsc ls m2 ${RATEUS}kbit
tc class add dev $DEV parent 1:1 classid 1:20 hfsc ls m2 ${RATEUS}kbit

# Add leaf classes

# Low Lat
tc class add dev $DEV parent 1:10 classid 1:11 hfsc sc umax 1500b dmax $LAT_MS rate ${RATE40}kbit
tc class add dev $DEV parent 1:20 classid 1:21 hfsc sc umax 1500b dmax $LAT_MS rate ${RATE40}kbit

# Normal
tc class add dev $DEV parent 1:10 classid 1:12 hfsc sc rate ${RATE40}kbit
tc class add dev $DEV parent 1:20 classid 1:22 hfsc sc rate ${RATE40}kbit

# Bulk
tc class add dev $DEV parent 1:10 classid 1:13 hfsc sc rate ${RATE20}kbit
tc class add dev $DEV parent 1:20 classid 1:23 hfsc sc rate ${RATE20}kbit

# iptables QoS chain
iptables -t mangle -N QoS_wan
iptables -t mangle -A PREROUTING ! -i $DEV -j QoS_wan
iptables -t mangle -A OUTPUT -j QoS_wan

# iptables MARK's - packet source (LAN/LOC)
# Default LAN (mark 1), unless from br-loc (overwrite with mark 2)
iptables -t mangle -A QoS_wan ! -i br-loc -j MARK --set-mark 0x0001
iptables -t mangle -A QoS_wan -i br-loc -j MARK --set-mark 0x0002

# tc filtering

# 1. Low Lat
for pspec in $LL_TCP
do
	w=${pspec%:*}
	port=${pspec#*:}
	if [ x"$w" == x"s" ]
	then
		way="sport"
	elif [ x"$w" == x"d" ]
	then
		way="dport"
	else
		echo "Illegal port specification: $pspec"
		continue
	fi
	tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x0001 0xffff match ip $way $port 0xffff match ip protocol 0x6 0xff flowid 1:11
	tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x0002 0xffff match ip $way $port 0xffff match ip protocol 0x6 0xff flowid 1:21
done
for port in $LL_UDP
do
	w=${pspec%:*}
	port=${pspec#*:}
	if [ x"$w" == x"s" ]
	then
		way="sport"
	elif [ x"$w" == x"d" ]
	then
		way="dport"
	else
		echo "Illegal port specification: $pspec"
		continue
	fi
	tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x0001 0xffff match ip $way $port 0xffff match ip protocol 0x11 0xff flowid 1:11
	tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x0002 0xffff match ip $way $port 0xffff match ip protocol 0x11 0xff flowid 1:21
done

# 2. Bulk
for port in $BU_TCP
do
	w=${pspec%:*}
	port=${pspec#*:}
	if [ x"$w" == x"s" ]
	then
		way="sport"
	elif [ x"$w" == x"d" ]
	then
		way="dport"
	else
		echo "Illegal port specification: $pspec"
		continue
	fi
	tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x0001 0xffff match ip $way $port 0xffff match ip protocol 0x11 0xff flowid 1:13
	tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x0002 0xffff match ip $way $port 0xffff match ip protocol 0x11 0xff flowid 1:23
done
for port in $BU_UDP
do
	w=${pspec%:*}
	port=${pspec#*:}
	if [ x"$w" == x"s" ]
	then
		way="sport"
	elif [ x"$w" == x"d" ]
	then
		way="dport"
	else
		echo "Illegal port specification: $pspec"
		continue
	fi
	tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x0001 0xffff match ip $way $port 0xffff match ip protocol 0x11 0xff flowid 1:13
	tc filter add dev $DEV parent 1:0 prio 1 u32 match mark 0x0002 0xffff match ip $way $port 0xffff match ip protocol 0x11 0xff flowid 1:23
done

# 3. Normal (Everything else)
tc filter add dev pppoe-wan parent 1:0 prio 1 u32 match mark 0x0001 0xffff flowid 1:12
tc filter add dev pppoe-wan parent 1:0 prio 1 u32 match mark 0x0002 0xffff flowid 1:22

echo QoS Started.
