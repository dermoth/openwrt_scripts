#!/bin/bash
#
# It is possible to permanently whitelist hosts by inserting a rule to
# the input_rule chainwith the RETURN target (the rules will still be
# appended there but will be skipped).

#TODO: Drop ip calc stuff, just insert rules at the top of the chain...

###############
RSYSLOGD_FIFO='/var/lib/sshfilter/pipe'

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
### DEBUG ###
# Fixed and read-only PATH
declare -xr PATH='/bin:/usr/bin:/sbin:/usr/sbin'

# Don't allow redefining these
declare -r NAME RSYSLOGD_FIFO FAIL_COUNT IP4_PREFIX IP6_PREFIX

trap_setup() {
	local sig
	shutdown() {
		local reason=$1 signal=${2:-SIGTERM}

		log notice "Shutting down on $reason"
		trap - EXIT  # Override catch-all exit trap
		trap - "${SIGNALS[@]}"  # Remove all handlers
		# Use kill command, pid 0 is pgroup
		command kill -s "$signal" 0
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
	logger --id=$$ -p "$prio" -t "$NAME" "$*" || :
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
if ! nft list set inet filter sshfilter4 >/dev/null ||
   ! nft list set inet filter sshfilter6 >/dev/null; then
	log crit "You must create sshfilter4 and sshfilter6 ipsets in filter first!"
	log crit "Use these ipsets to setup your filtering rules, this tool updates them."
	exit 1
fi

#
### Brute force
#
#2024-09-14T15:32:09.000000-04:00 dermoth sshd[2171469]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=62.106.95.50  user=root
#2024-09-14T15:32:11.000000-04:00 dermoth sshd[2171469]: Failed password for root from 62.106.95.50 port 46402 ssh2
#2024-09-14T15:32:12.000000-04:00 dermoth sshd[2171469]: Received disconnect from 62.106.95.50 port 46402:11: Bye Bye [preauth]
#2024-09-14T15:32:12.000000-04:00 dermoth sshd[2171469]: Disconnected from authenticating user root 62.106.95.50 port 46402 [preauth]
#
#2024-09-14T15:38:14.000000-04:00 dermoth sshd[2172987]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=92.255.85.253  user=root
#2024-09-14T15:38:17.000000-04:00 dermoth sshd[2172987]: Failed password for root from 92.255.85.253 port 56440 ssh2
#2024-09-14T15:38:17.000000-04:00 dermoth sshd[2172987]: Connection reset by authenticating user root 92.255.85.253 port 56440 [preauth]
#
#Apr 18 16:00:19 dermoth sshd[701474]: Invalid user admin from 85.209.11.27 port 14148
#Apr 18 16:00:19 dermoth sshd[701474]: Failed none for invalid user admin from 85.209.11.27 port 14148 ssh2
#Apr 18 16:00:20 dermoth sshd[701474]: Connection closed by invalid user admin 85.209.11.27 port 14148 [preauth]
#
#Apr 18 15:15:56 dermoth sshd[693673]: Invalid user gitlab-runner from 170.64.234.117 port 38470
#Apr 18 15:15:59 dermoth sshd[693673]: Failed password for invalid user gitlab-runner from 170.64.234.117 port 38470 ssh2
#Apr 18 15:16:00 dermoth sshd[693673]: Connection closed by invalid user gitlab-runner 170.64.234.117 port 38470 [preauth]
#
# Variant, logs crit but likely just caused by client disconnect
#
#Apr 18 18:30:42 dermoth sshd[726281]: Invalid user admin from 178.176.193.56 port 58947
#Apr 18 18:30:44 dermoth sshd[726281]: Failed password for invalid user admin from 178.176.193.56 port 58947 ssh2
#Apr 18 18:32:40 dermoth sshd[726281]: fatal: Timeout before authentication for 178.176.193.56 port 58947
#
# # Variant, keeps trying (most appears to try avoiding too many attemps message!)
#
#Jun 12 16:57:57 dermoth sshd[1019340]: Invalid user test from 211.114.124.31 port 51380
#Jun 12 16:57:59 dermoth sshd[1019340]: Failed password for invalid user test from 211.114.124.31 port 51380 ssh2
#Jun 12 16:58:01 dermoth sshd[1019340]: Failed password for invalid user test from 211.114.124.31 port 51380 ssh2
#Jun 12 16:58:04 dermoth sshd[1019340]: Failed password for invalid user test from 211.114.124.31 port 51380 ssh2
#Jun 12 16:58:09 dermoth sshd[1019340]: Failed password for invalid user test from 211.114.124.31 port 51380 ssh2
#Jun 12 16:58:13 dermoth sshd[1019340]: Failed password for invalid user test from 211.114.124.31 port 51380 ssh2
#Jun 12 16:58:16 dermoth sshd[1019340]: Failed password for invalid user test from 211.114.124.31 port 51380 ssh2
#Jun 12 16:58:18 dermoth sshd[1019340]: error: maximum authentication attempts exceeded for invalid user test from 211.114.124.31 port 51380 ssh2 [preauth]
#Jun 12 16:58:18 dermoth sshd[1019340]: Disconnecting invalid user test 211.114.124.31 port 51380: Too many authentication failures [preauth]
#
### Protocol attack?
#
#May 01 12:58:47 dermoth sshd[2711815]: Corrupted MAC on input. [preauth]
#May 01 12:58:47 dermoth sshd[2711815]: ssh_dispatch_run_fatal: Connection from 178.118.89.82 port 56512: message authentication code incorrect [preauth]
#
#May 26 23:18:52 dermoth sshd[97540]: Failed password for root from 218.92.0.24 port 51181 ssh2
#May 26 23:18:53 dermoth sshd[97540]: Bad packet length 202642480. [preauth]
#May 26 23:18:53 dermoth sshd[97540]: ssh_dispatch_run_fatal: Connection from authenticating user root 218.92.0.24 port 51181: message authentication code incorrect [preauth]
#
#May 01 15:29:35 dermoth sshd[2739822]: ssh_dispatch_run_fatal: Connection from 99.46.3.41 port 39706: Connection corrupted [preauth]
#
### Trying vulnerable algos?
#
#2024-09-14T15:16:50.000000-04:00 dermoth sshd[2167258]: Unable to negotiate with 88.214.25.16 port 22352: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 [preauth]
#
#2024-09-14T15:16:53.000000-04:00 dermoth sshd[2167275]: Unable to negotiate with 88.214.25.16 port 50149: no matching host key type found. Their offer: ssh-rsa,ssh-dss [preauth]
#
#Apr 26 17:36:46 dermoth sshd[1648106]: Invalid user admin from 139.19.117.130 port 43196
#Apr 26 17:36:46 dermoth sshd[1648106]: userauth_pubkey: signature algorithm ssh-rsa not in PubkeyAcceptedAlgorithms [preauth]
#Apr 26 17:36:55 dermoth sshd[1648106]: Connection closed by invalid user admin 139.19.117.130 port 43196 [preauth]
#
### Protocol attack?
#
#Jun 12 23:46:28 dermoth sshd[1028022]: error: kex_exchange_identification: client sent invalid protocol identifier "MGLNDD_66.158.157.66_22"
#Jun 12 23:46:28 dermoth sshd[1028022]: banner exchange: Connection from 4.151.220.155 port 42950: invalid format
#
#Apr 24 18:57:48 dermoth sshd[1482652]: error: kex_protocol_error: type 20 seq 2 [preauth]
#Apr 24 18:57:48 dermoth sshd[1482652]: error: kex_protocol_error: type 30 seq 3 [preauth]
#Apr 24 18:58:18 dermoth sshd[1482652]: Connection reset by 164.92.164.19 port 61000 [preauth]
#
#Apr 26 18:36:46 dermoth sshd[1651731]: Invalid user admin from 139.19.117.130 port 50520
#Apr 26 18:36:46 dermoth sshd[1651731]: error: userauth_pubkey: parse key: invalid format [preauth]
#Apr 26 18:36:46 dermoth sshd[1651731]: error: userauth_pubkey: parse key: invalid format [preauth]
#Apr 26 18:36:56 dermoth sshd[1651731]: Connection closed by invalid user admin 139.19.117.130 port 50520 [preauth]
#
#Sep 04 14:01:37 dermoth sshd[210405]: Invalid user NL5xUDpV2xRa from 203.146.190.62 port 24831
#Sep 04 14:01:37 dermoth sshd[210405]: fatal: userauth_pubkey: parse publickey packet: incomplete message [preauth]
#
#Apr 21 08:25:30 dermoth sshd[1119599]: error: kex_exchange_identification: banner line contains invalid characters
#Apr 21 08:25:30 dermoth sshd[1119599]: banner exchange: Connection from 194.169.175.42 port 63006: invalid format
#
#
# Matching rules
#
# crit
#fatal: Timeout before authentication for * (ignore, match prior events)
#
# err
#error: maximum authentication attempts exceeded for{ ,invalid user} * from * (ignore, match individual attempts)
#
# info
#Accepted password for {root,dermoth_work,dermoth}
#banner exchange: Connection from *
#Connection closed by{, authenticating, invalid} user *
#Connection reset by{, authenticating, invalid} *
#{Disconnecting,Disconnected from} {user ,authenticating user ,invalid user ,[0-9]}*
# Failed none for invalid user *
#Failed password for *
#Invalid user *
#Received disconnect from *
#Received disconnect from .*:11: disconnected by user*
#Server listening on *
#ssh_dispatch_run_fatal: Connection from *
#Unable to negotiate with *

# Matching rules
#
# TODO: Startup/reload rule, import ruleset from journalctl (-2592000 is from one month ago)
#   journalctl -S '-2592000' -t sshd -qo short-iso-precise --facility=auth --priority info..info > "$RSYSLOGD_FIFO"

filter() {
	local time=$1 hostn=$2 proc=$3 msg=$4
	local ipport

	#log info "$time $hostn $proc $msg"

	# TODO: rsyslog config
	#case $fnprio in
	#	authpriv.info|authpriv.warn)
	#		;;

	case $proc in
		sshd\[*\]:)
			;;
		*)
			log warn "Unexpected proc: $proc"
			return
	esac

	case $msg in
		*\ from\ *\ port\ *)
			;;
		*)
			# We could possibly keep track of relevant context using pid...
			return  # Nothing to do
	esac

	case $msg in
		Failed\ password\ for\ *\ from\ *\ port\ *)
			ipport=${msg#Failed password for * from }
			;;

		# Possible attacks, consider instnt blacklist
		Unable\ to\ negotiate\ with\ *\ port\ *)
			ipport=${msg#Unable to negotiate with }
			;;
		banner\ exchange:\ Connection\ from\ *\ port\ *)
			ipport=${msg#banner exchange: Connection from }
			;;
		Invalid\ user\ *\ from\ *)
			# This effectively doubles the error rate for invalid users!
			ipport=${msg#Invalid user * from }
			;;
		ssh_dispatch_run_fatal:\ Connection\ from\ *)
			ipport=${msg#ssh_dispatch_run_fatal: Connection from }
			ipport=${ipport#authenticating user * }
			;;
		Unable\ to\ negotiate\ with\ *)
			ipport=${msg#Unable to negotiate with }
			;;

		# Ignored entries
		Accepted\ password\ for\ *)
			# Should we reset the stats counter?
			return
			;;
		Connection\ closed\ by\ *|Connection\ reset\ by\ *|Disconnecting\ *|Disconnected\ from\ *|Received\ disconnect\ from\ *)
			return
			;;
		Failed\ none\ for\ invalid\ user\ *)
			# 3rd match on invalid users... Just ignore
			return
			;;
		Server\ listening\ on\ *)
			return
			;;
		*)
			log notice "Unmatch: $time $hostn $proc $msg"
			return
	esac

	if ! [ -v ipport ]; then
		log warn "Possible missed extraction: $time $hostn $proc $msg"
		return
	fi
	ipport=${ipport/ port /:}
	ipport=${ipport%%: *}  # Don't cut port, include space after colon

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
				nft "add element inet filter sshfilter4 { $retval/$IP4_PREFIX }"
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
				nft "add element inet filter sshfilter6 { $retval/$IP6_PREFIX }"
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

# Open for writing too so we don't block or get SIGPIPE on rsyslogd restarts
exec <>"$RSYSLOGD_FIFO"

# Main loop...
while read -r time hostn proc msg; do
	filter "$time" "$hostn" "$proc" "$msg"
done
