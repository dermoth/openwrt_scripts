#!/bin/bash
#
# It is possible to permanently whitelist hosts by inserting a rule to
# the input_rule chainwith the RETURN target (the rules will still be
# appended there but will be skipped).

#TODO: Drop ip calc stuff, just insert rules at the top of the chain...

###############

# Whitelist networks (an interface here will add its network to the whitelist)
WL_NETS="192.168.1.0/24 loc"  # FIXME: TODO

WL_INTS="br-lan br-loc"

###############

set -eu

NAME=${0##*/}

# logger's pidfile
PIDFILE=/var/run/${NAME%.*}-logread.pid

# Fixed and read-only PATH
declare -xr PATH='/bin:/usr/bin:/sbin:/usr/sbin'

# Don't allow redefining these
declare -r WL_NETS WL_INTS NAME PIDFILE

trap_setup() {
	local sig
	shutdown() {
		local reason=$1

		log notice "Shutting down on $reason"
		[ -e "$PIDFILE" ] && kill "$(<"$PIDFILE")"
		trap - EXIT  # Override catch-all exit trap
	}

	trap 'shutdown "fatal error at line $LINENO"' ERR

	# Everything else (logread died or unhandled signal)
	trap 'shutdown "unknown signal"' EXIT
	# Catch most common signals
	for sig in HUP INT QUIT ABRT ALRM TERM USR1 USR2; do
		trap "shutdown 'SIG$sig ($(kill -l "SIG$sig"))'" "SIG$sig"
	done
}
trap_setup

log() {
	# Params: prio messages...
	local prio=$1
	shift
	logger -p "$prio" -t "${NAME}[$$]" "$*" || :
}

#nets_from_iface() {
#}

_isnibble4() {
	# Contains only digits?
	[ -z "${1//[0-9]}" ] || return 1
	# Check range
	(($1 <= 255)) || return 1
	return 0
}

_isnibble6() {
	# Contains only hex digits?
	[ -z "${1//[0-9a-fA-F]}" ] || return 1
	# Check length
	[ ${#1} -le 4 ] || return 1
	return 0
}

ip42long() {
	local i ret=0 offset=24
	local -a nibbles
	IFS=. read -a nibbles <<<"$1"
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
	retval=$ret
}

long2ip4() {
	if [ $1 -lt 0 ] || [ $1 -gt 4294967295 ]; then
		log err "long2ip4: Long out of range: $1"
		return 1
	fi
	local a=$(($1>>24 & 255)) b=$(($1>>16 & 255)) c=$(($1>>8 & 255)) d=$(($1 & 255))
	printf -v retval '%d.%d.%d.%d\n' "$a" "$b" "$c" "$d"
}

ip62hex() {
	local i j gap ret= offset=24
	local -a nibbles
	# Check for single trailing : (uncaught otherwise)
	if [ "${1/%[!:]:}" != "$1" ]; then
		log err "Invalid IPv6: Trailing colon: $1"
		return 1
	fi
	IFS=: read -a nibbles <<<"$1"

	i=${#nibbles[@]}
	gap=$((8-i))
	for ((i=0; i<8; i++)); do
		if [ ! -v nibbles[i] ]; then
			# FIXME: Sounds broken, where is gap handled?
			log err "Invalid IPv6 (or confused myself): $1"
			return 1
		elif [ -z "${nibbles[i]}" ]; then
			if ((gap<0)); then
				log err "Invalid IPv6: Too many blanks: $1"
				return 1
			elif ((i==0)); then
				# Read counts leading empty fields but not trailing
				((++i))  # Read counts leading empty fielsd but not trailing
				ret+='0000'
			fi
			# Move nibbles after gap
			for ((j=7; j>=i+gap; j--)); do
				nibbles[j]=${nibbles[j-gap]}
			done
			# Fill gap
			for ((; i<=j; i++)); do
				nibbles[i]=
				ret+='0000'
			done
			gap=-1  # So we know he processed one
			ret+='0000'
			continue
			#((i+=gap))
		elif _isnibble6 "${nibbles[i]}"; then
			printf -v ret '%s%04x' "$ret" "$((16#${nibbles[i]}))"
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

match() {
	local var=$1 match=$2
	case ${!var} in
		$match) return 0
	esac
	return 1
}

# First add/replace whitelist entries

log notice "Started"

for int in $WL_INTS; do
	log info "(Re-)Adding whitelist rule for $int"
	iptables -D input_rule -i $int -j RETURN || :
	iptables -I input_rule 1 -i $int -j RETURN
done

set +u
declare -a counts
#Mon Oct 25 04:22:26 2021 authpriv.warn dropbear[24043]: Bad password attempt for 'root' from 101.132.98.26:45201
while read -r dow mon day time year fnprio proc msg; do
	log info "$dow $mon $day $time $year $fnprio $proc $msg"

	match fnprio authpriv.warn || continue
	match proc 'dropbear*' || continue
	match msg 'Bad password attempt for * from *' || continue

	ipport=${msg##*from }
	if match ipport '*.*.*.*:*'; then
		ipaddr=${ipport%:*}
		ip42long "$ipaddr"
		if ((++counts[retval] > 10)); then
			unset counts[retval]
			log notice "10 attempts from $ipaddr - thanks you have a good day..."
			iptables -A input_rule -p tcp -s "$ipaddr" -j DROP
		fi
	else
		log warn "Unexpected match (IPv6?): $ipport"
	fi
done < <(logread -f -e '^dropbear.\+Bad password attempt for' -p "$PIDFILE")
