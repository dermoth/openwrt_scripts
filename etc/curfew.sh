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

set -eu

usage() {
	echo "Usage: $0 {start|stop|status}"
	exit 1
}

set_rule() {
	ruleid=$1
	method=$2

	case $method in
		enable)
			uci delete "firewall.@rule[$ruleid].enabled=0"
			;;
		disable)
			uci set "firewall.@rule[$ruleid].enabled=0"
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

case ${1:-help} in
	start)
		echo "curfew: Enabling rules..."
		foreach_cf enable
		uci commit
		echo "curfew: Reloading firewall rules..."
		/etc/init.d/firewall reload >/dev/null 2>&1
		echo "curfew: Started OK"
		;;
	stop)
		echo "curfew: Enabling rules..."
		foreach_cf disable
		uci commit
		echo "curfew: Reloading firewall rules..."
		/etc/init.d/firewall reload >/dev/null 2>&1
		echo "curfew: Stoped OK"
		;;
	status)
		foreach_cf show
		;;
	*)
		usage
esac
