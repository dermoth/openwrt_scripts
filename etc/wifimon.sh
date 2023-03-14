#!/bin/bash
#
# Restart wifi when seeing these in repetition:
#   Sun Mar 12 09:15:01 2023 daemon.err hostapd: Failed to set beacon parameters

###############

# Trigger facility.priority match
TRIGGERFP=daemon.err

# Trigger process match (has to match [pid] / trailing colon too)
TRIGGERPS='hostapd:'

# Logread match - should match same as above, using regex
LOGREADRE='^hostapd:'

# Trigger log message match
TRIGGERLM='Failed to set beacon parameters'

# Trigger wifi restart after this number of successive messages
TRIGERCNT=10

# Restart delay between "wifi down" and "wifi up"
SLEEPTIME=3

###############

set -eu

NAME=${0##*/}

# logger's pidfile
PIDFILE=/var/run/${NAME%.*}-logread.pid

# Fixed and read-only PATH
declare -xr PATH='/bin:/usr/bin:/sbin'

# Don't allow redefining these
declare -r TRIGGERFP TRIGGERPS LOGREADRE TRIGGERLM TRIGERCNT SLEEPTIME NAME PIDFILE

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

match() {
	local var=$1 match=$2
	case ${!var} in
		$match) return 0
	esac
	return 1
}

wifi_restart() {
	log emerg "Restarting wifi after $TRIGERCNT matching messages"
	wifi down
	sleep "$SLEEPTIME"
	wifi up
	log notice "Wifi restarted (rc=$?)"
}

log notice "Started"

#Mon Oct 25 04:22:26 2021 authpriv.warn dropbear[24043]: Bad password attempt for 'root' from 101.132.98.26:45201
#Sun Mar 12 09:15:01 2023 daemon.err hostapd: Failed to set beacon parameters
count=0
while read -r dow mon day time year fnprio proc msg
do
	match fnprio "$TRIGGERFP" || continue
	match proc "$TRIGGERPS" || continue

	# Count subsequent messages
	if match msg "$TRIGGERLM"; then
		((++count))
	else
		count=0
	fi

	if ((count >= TRIGERCNT)); then
		count=0
		# Run restart unconditionally (ignore failures)
		wifi_restart || :
	fi
	log notice "$dow $mon $day $time $year $fnprio $proc $msg count=$count"
done < <(trap - EXIT; logread -f -e "$LOGREADRE" -p "$PIDFILE")
