#!/bin/bash
#
# It is possible to permanently whitelist hosts by inserting a rule to
# the input_rule chainwith the RETURN target (the rules will still be
# appended there but will be skipped).

#TODO: Drop ip calc stuff, just insert rules at the top of the chain...

###############

# Count of failures to blacklist
FAIL_COUNT=10

# IPv4 block prefix
IP4_PREFIX=24

# IPv6 block prefix
IP6_PREFIX=48

###############

set -eu

NAME=${0##*/}

# Handled signals
SIGNALS=(HUP INT QUIT ABRT ALRM USR1 USR2 PIPE TERM)

### DEBUG ###
#iptables() {
#	echo iptable "${@@Q}"
#}
#nft() {
#	echo nft "${@@Q}"
#}
#logger() {
#	# Assumes argument order from log() !!
#	case $2 in
#		debug) return;;
#		info)  return;;
#	esac
#	echo log "${*:4}"
#}
#logread() {
#	# Assumes argument order from logread() !!
#	grep 'dropbear' /var/log/openwrt.log.1 /var/log/openwrt.log |
#		while read -r _ hn msg; do
#			[ "$hn" == OpenWrt ] || continue
#			printf '%s\n' "$msg"
#		done |
#	grep "$3" |
#	sed 's/^/Thu Jan 01 00:00:00 1970 authpriv.warn /'
#}
### DEBUG ###

# logger's pidfile
PIDFILE=/var/run/${NAME%.*}-logread.pid

# Fixed and read-only PATH
declare -xr PATH='/bin:/usr/bin:/sbin:/usr/sbin'

# Don't allow redefining these
declare -r NAME PIDFILE FAIL_COUNT IP4_PREFIX IP6_PREFIX

trap_setup() {
	local sig
	shutdown() {
		local reason=$1 signal=${2:-SIGTERM}

		log notice "Shutting down on $reason"
		trap - EXIT  # Override catch-all exit trap
		trap - "${SIGNALS[@]}"  # Remove all handlers
		if [ -e "$PIDFILE" ]; then
			kill "$(<"$PIDFILE")"
		else
			# Use kill command, pid 0 is pgroup
			command kill -s "$signal" 0
		fi
	}

	trap 'shutdown "fatal error at line $LINENO"' ERR

	# Everything else (logread died or unhandled signal)
	trap 'shutdown "unknown signal"' EXIT
	# Catch most common signals
	for sig in "${SIGNALS[@]}"; do
		# shellcheck disable=SC2064  # progrmatic trap setup
		trap "shutdown 'SIG$sig ($(kill -l "SIG$sig"))' SIG$sig" "SIG$sig"
	done
}
trap_setup

log() {
	# Params: prio messages...
	local prio=$1
	shift
	logger -p "$prio" -t "${NAME}[$$]" "$*" || :
}

_isnibble4() {
	# Contains only digits?
	[ -z "${1//[0-9]}" ] || return 1
	# Check range
	(($1 <= 255)) || return 1
	return 0
}

_ismask4() {
	[ "$1" -ge 0 ] && [ "$1" -le 32 ] && return 0
	return 1
}

_isnibble6() {
	# Contains only hex digits?
	[ -z "${1//[0-9a-fA-F]}" ] || return 1
	# Check length
	[ ${#1} -le 4 ] || return 1
	return 0
}

_ismask6() {
	[ "$1" -ge 0 ] && [ "$1" -le 128 ] && return 0
	return 1
}


ip42long() {
	local i prefix mask ret=0
	local -a nibbles
	IFS=. read -r -a nibbles <<<"$1"
	prefix=${2:-32}
	if ! _ismask4 "$prefix"; then
		log err "ip42long: Invalid mask: $prefix"
	fi
	if [ ${#nibbles[@]} -ne 4 ]; then
		log err "ip42long: Invalid IPv4: $1"
		return 1
	fi
	for ((i=0; i<4; i++)); do
		if _isnibble4 "${nibbles[i]}"; then
			# Shift ret, add nibble (last 1 makes statement always true)
			((ret=ret<<8, ret+=10#${nibbles[i]}, 1))
		else
			log err "ip42long: Invalid IPv4 nibble (idx-$i): ${nibbles[i]} ($1)"
			return 1
		fi
	done
	mask=$(( ((1 << prefix) - 1) << (32-prefix) ))
	ret=$((ret & mask))
	retval=$ret
}

long2ip4() {
	if [ "$1" -lt 0 ] || [ "$1" -gt 4294967295 ]; then
		log err "long2ip4: Long out of range: $1"
		return 1
	fi
	local a=$(($1>>24 & 255)) b=$(($1>>16 & 255)) c=$(($1>>8 & 255)) d=$(($1 & 255))
	printf -v retval '%d.%d.%d.%d' "$a" "$b" "$c" "$d"
}

ip62hex() {
	local i j gap prefix subpfx mask ret=
	local -a nibbles
	# Check for single trailing : (uncaught otherwise)
	if [ "${1/%[!:]:}" != "$1" ]; then
		log err "Invalid IPv6: Trailing colon: $1"
		return 1
	fi
	IFS=: read -r -a nibbles <<<"$1"
	prefix=${2:-128}
	if ! _ismask6 "$prefix"; then
		log err "ip42long: Invalid mask: $prefix"
	fi

	i=${#nibbles[@]}
	gap=$((8-i))

	# FIXME: leading or trailing :: with no gap: replace with leading or trailing 0000

	for ((i=0; i<8; i++)); do

		if [ ! -v 'nibbles[i]' ]; then
			log err "Invalid IPv6 (missing nibble): $1"
			return 1
		elif [ -z "${nibbles[i]}" ]; then
			if ((gap<0)); then
				log err "Invalid IPv6: Too many blanks: $1"
				return 1
			elif ((i==0)); then
				# Read counts leading empty fields but not trailing
				((++i))  # Read counts leading empty fields but not trailing
				prefix=$((prefix-16))  # Eat prefix but no need to AND as it's 0 already
				ret+='0000'
			fi
			# Move nibbles after gap
			for ((j=7; j>=i+gap; j--)); do
				nibbles[j]=${nibbles[j-gap]}
			done
			# Fill gap
			for ((; i<=j; i++)); do
				nibbles[i]=
				prefix=$((prefix-16))  # Eat prefix but no need to AND as it's 0 already
				ret+='0000'
			done
			gap=-1  # So we know he processed one
			prefix=$((prefix-16))  # Eat prefix but no need to AND as it's 0 already
			ret+='0000'
			continue
		elif _isnibble6 "${nibbles[i]}"; then
			# Get prefix for this 16-bit nibble)
			subpfx=$((prefix > 0 ? prefix : 0))
			prefix=$((prefix-16))
			subpfx=$((prefix > 0 ? subpfx - prefix : subpfx))
			mask=$(( ((1 << subpfx) - 1) << (16-subpfx) ))
			printf -v ret '%s%04x' "$ret" "$((16#${nibbles[i]} & mask))"
		else
			log err "Invalid IPv6 nibble (idx=$i): ${nibbles[i]} ($1)"
			return 1
		fi
	done
	retval=$ret
}

hex2ip6() {
	local i tmp gappos gaplen=0 ret=
	if [ -n "${1//[0-9a-fA-F]}" ]; then
		log err "Invalid hex: $1"
		return 1
	elif [ ${#1} -ne 32 ]; then
		log err "Invalid hex lenght (${#1})"
		return 1
	fi

	# Find longest gap
	for ((i=32; i>=4; i-=4)); do
		printf -v tmp "%0${i}i" 0
		if [ "${1/$tmp}" != "$1" ]; then
			gaplen=$i
			tmp=${1/$tmp/:}
			tmp=${tmp%:*}
			gappos=$((${#tmp}))
			break
		fi
	done

	tmp=':'
	for ((i=0; i<=28; i+=4)); do
		if ((gaplen && i==gappos)); then
			# Fill up gap

			printf -v ret "%s:" "$ret"
			((i+=gaplen-4))
			((i==28)) && ret+=:  # Gap at the end, append trailing :
			continue
		fi
		printf -v ret "%s%s%x" "$ret" "${ret:+:}" "$((16#${1:$i:4}))"
	done
	retval=$ret
}

# We no longer install our config directly, instead rely on existing rules
if ! nft list set inet fw4 sshfilter4 >/dev/null ||
   ! nft list set inet fw4 sshfilter6 >/dev/null; then
	log crit "You must create sshfilter4 and sshfilter6 ipsets in fw4 first!"
	log crit "Use these ipsets to setup your filtering rules, this tool updates them."
	exit 1
fi

# Do we create our own table or hook into fw4 ??
#drop first.... then
#nft add chain inet fw4 ssh_filter
#nft add rule inet fw4 input_wan tcp dport 22 jump ssh_filter
##### nft add rule inet fw4 ssh_filter ip saddr 64.23.184.171 drop
# Or include here:
#/usr/share/nftables.d/chain-pre/input_wan/ssh_filter.nft
#/usr/share/nftables.d/chain-pre/input_wan/ssh_filter.nft
# Or
# For example, to add custom logging to the input_wan chain:
#
# # /etc/config/firewall
#config include
#	option	type		'nftables'
#	option	path		'/etc/sshfilter_persist.nft'
#	option	position	'chain-pre'
#	option	chain		'ssh_filter'
#
# # /etc/sshfilter_persist.nft  TODO: use ipsets
#ip saddr 64.23.184.171 drop
#
# To add one or more custom chains:
#
#config include
#	option	type		'nftables'
#	option	path		'/etc/sshfilter_chain.nft'
#	option	position	'table-post'
# OR use named set (already configured!!
#nft add element inet fw4 sshfilter4 { 64.23.184.171 }
#nft add element inet fw4 sshfilter6 { 2001:56b:9fef:c6b3:0:3b:e9ef:601 }  # DON'T ADD - MY PHONE
# Possibly add persist file, loas using hooks

filter() {
	local dow=$1 mon=$2 day=$3 time=$4 year=$5 fnprio=$6 proc=$7 msg=$8
	local ipport

	log info "$dow $mon $day $time $year $fnprio $proc $msg"

	case $fnprio in
		authpriv.info|authpriv.warn)
			;;
		*)
			log warn "Unexpected fnprio: $fnprio"
			return
			;;
	esac

	case $proc in
		dropbear\[*\]:)
			;;
		*)
			log warn "Unexpected proc: $proc"
			return
	esac

	case $msg in
		Bad\ password\ attempt\ for\ *\ from\ *)
			ipport=${msg##*from }
			;;
		Exit\ before\ auth\ from\ \<*\>:*Exited\ normally)
			ipport=${msg##*from <}
			ipport=${ipport%%>*}
			;;
		Exit\ before\ auth\ from\ \<*\>:*)
			# Likely hack attempts, may be more aggessive for these
			ipport=${msg##*from <}
			ipport=${ipport%%>*}
			;;
		*)
			log notice "Unmatch: $dow $mon $day $time $year $fnprio $proc $msg"
			return
	esac

	if ! [ -v ipport ]; then
		log warn "Possible missed extraction: $dow $mon $day $time $year $fnprio $proc $msg"
		return
	fi

	case $ipport in
		?*.?*.?*.?*:?*)
			ipaddr=${ipport%:*}
			ip42long "$ipaddr" "$IP4_PREFIX"
			ipaddr=$retval
			long2ip4 "$retval"
			if ((++counts[$ipaddr] > FAIL_COUNT)); then
				#unset counts[$ipaddr]
				counts[$ipaddr]=-100000000
				log notice "$FAIL_COUNT attempts from $retval/$IP4_PREFIX - thanks you have a good day..."
				nft "add element inet fw4 sshfilter4 { $retval/$IP4_PREFIX }"
			fi
			;;
		?*:?*:?*:?*:?*:?*:?*:?*:?*|?*::?*:?*|?*:::?*)
			ipaddr=${ipport%:*}
			ip62hex "$ipaddr" "$IP6_PREFIX"
			ipaddr=$retval
			hex2ip6 "$retval"
			if ((++count6[$ipaddr] > FAIL_COUNT)); then
				#unset "count6[$ipaddr]"
				count6[$ipaddr]=-100000000
				log notice "$FAIL_COUNT attempts from $retval/$IP6_PREFIX - thanks you have a good day..."
				nft "add element inet fw4 sshfilter6 { $retval/$IP6_PREFIX }"
			fi
			;;
		::?*)
			log warn "Connection from loopback: $ipport"
			;;
		*)
			log warn "Unexpected match: $ipport"
	esac
}

log notice "Started"

set +u
declare -A counts count6

#Mon Oct 25 04:22:26 2021 authpriv.warn dropbear[24043]: Bad password attempt for 'root' from 101.132.98.26:45201
# Main loop...
while read -r dow mon day time year fnprio proc msg; do
	filter "$dow" "$mon" "$day" "$time" "$year" "$fnprio" "$proc" "$msg"
done < <(logread -f -e '^dropbear.\+\(Bad password attempt for\|Exit before auth from\)' -p "$PIDFILE")
