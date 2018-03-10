#!/bin/sh
#
# Firewall Curfew script for OpenWRT
#
# Author: Thomas Guyot-Sionnest <tguyot@gmail.com>
#   This script has been released into the public domain.
#
# This script enables or disables all traffic rules begining in "$RULE_PREFIX"
# defined below. The variable can also be passed as an environment variable to
# the script
#
# Usage: ./curfew.sh { start | stop | status }
#
#   start:  Start the curfew - enable the rules to block traffic
#   stop:   Stop the curfew - disable the rules to re-enable traffic
#   status: Show current rule status
#
# This script should be placed in the system crontab. For example, to disable
# traffic using mathing rules from 7PM to 7 AM use the follwoing two entries:
#
#   00 19 * * * /etc/curfew.sh start
#   00 07 * * * /etc/curfew.sh stop
#
# This script has been tested on Barrier Breaker (14.07) and requires UCI (on
# which LuCI - the standard web management interface - is based)
#

RULE_PREFIX=${RULE_PREFIX-"CF_"}
CONNTRACK_BIN="/usr/sbin/conntrack"

set -eu

usage() {
	echo "Usage: $0 { start | stop | status }"
	exit 1
}

set_rule() {
	ruleid=$1
	method=$2

	case $method in
		enable)
			uci -q delete "firewall.@rule[$ruleid].enabled=0" || true
			;;
		disable)
			uci set "firewall.@rule[$ruleid].enabled=0"
			;;
		flush)
			flushmac $(uci get "firewall.@rule[$ruleid].src_mac")
			;;
		show)
			name=$(uci get "firewall.@rule[$ruleid].name")
			enabled=$(uci get "firewall.@rule[$ruleid].enabled" 2>/dev/null) || enabled=1
			echo "$name: enabled=$enabled"
			;;
		*)
			echo "set_rule: Invalid argument: $method"
			exit 1
	esac
}

foreach_cf() {
	method=$1

	i=0
	while [ $i -lt $((2**32)) ]
	do
		rulename=$(uci get "firewall.@rule[$i].name" 2>/dev/null) || break
		idx=$i
		let ++i
		[ "${rulename:0:${#RULE_PREFIX}}" == "$RULE_PREFIX" ] || continue
		set_rule $idx $method
	done
}

flushmac() {
	mac=$1

	iparpt=$(awk 'BEGIN{IGNORECASE=1} /'$mac'/ {print $1}' /proc/net/arp)
	ipdhcp=$(awk 'BEGIN{IGNORECASE=1} /'$mac'/ {print $3}' /tmp/dhcp.leases)

	# Log both on mismatch but always use lease file until we know one's more reliable
	if [ "$iparpt" != "$ipdhcp" ]
	then
		logger -t "$(basename "$0")" "WARN: ip mismatch (arp:leases): $iparpt:$ipdhcp"
	else
		if [ -n "$ipdhcp" ]
		then
			logger -t "$(basename "$0")" "Resolved $mac to $ipdhcp from /tmp/dhcp.leases"
		else
			logger -t "$(basename "$0")" "Couldn't resolve $mac to an IP address: nothing to flush"
			return
		fi
	fi

	# Retain only STDERR from conntrack but send it to STDOUT for logging
	# NB: Looks like I need only the first of each set, but it can't hurt...
	logger -t "$(basename "$0")" "src=$ipdhcp: $($CONNTRACK_BIN -D -s "$ipdhcp" 2>&1 1>/dev/null || true)"
	logger -t "$(basename "$0")" "dst=$ipdhcp: $($CONNTRACK_BIN -D -d "$ipdhcp" 2>&1 1>/dev/null || true)"
	logger -t "$(basename "$0")" "reply-src=$ipdhcp: $($CONNTRACK_BIN -D -r "$ipdhcp" 2>&1 1>/dev/null || true)"
	logger -t "$(basename "$0")" "reply-dst=$ipdhcp: $($CONNTRACK_BIN -D -q "$ipdhcp" 2>&1 1>/dev/null || true)"
}

fwreload() {
	logger -t "$(basename "$0")" "Reloading firewall..."
	/etc/init.d/firewall reload >/dev/null 2>&1
}

termlogger() {
	shift
	echo "$@"
}

if [ -t 1 ]
then
	# Use terminal output if running interactively
	alias logger=termlogger
else
	# Otherwise log errors
	exec >/tmp/curfew.$RULE_PREFIX.log 2>&1
fi

# OpenWRT add user rules after contrack rule, make sure we can flush them
if [ -x "$CONNTRACK_BIN" ]
then
	# nf_conntrack_netlink is needed; load it is not present.
	[ -d /sys/module/nf_conntrack_netlink ] || modprobe nf_conntrack_netlink
else
	logger -t "$(basename "$0")" "$CONNTRACK_BIN: Not found; will not be able to flush established connections"
	CONNTRACK_BIN=""
fi

case ${1:-help} in
	start)
		logger -t "$(basename "$0")" "Enabling rules..."
		foreach_cf enable
		uci commit

		# Reload firewall

		fwreload

		# Flush all established connections for these rules
		if [ -n "$CONNTRACK_BIN" ]
		then
			foreach_cf flush
		fi
		logger -t "$(basename "$0")" "Started OK"
		;;
	stop)
		logger -t "$(basename "$0")" "Disabling rules..."
		foreach_cf disable
		uci commit

		# Reload firewall
		fwreload
		logger -t "$(basename "$0")" "Stoped OK"
		;;
	status)
		foreach_cf show
		;;
	*)
		usage
esac

