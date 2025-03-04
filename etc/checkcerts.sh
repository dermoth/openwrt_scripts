#!/bin/bash
#
# Checks certificates validity
#

# Hostnames with port to check
HOSTNAMES=(
	www.example.com:80
)

# Expiry warning date in GNU date -d format
EXPIRE_WARN='1 month'

checkcert() {
	local host=$1 port=$2 warntime=$3 result=0 subject notAfter

	while read -r line; do
		case $line in
			subject=*|notAfter=*)
				local "$line"
				;;
			*)
				echo "ERROR: Unexpected line from openssl-x509: $line"
				exit 3
		esac
	done < <(
		openssl s_client -connect "$host:$port" </dev/null 2>&1 |
			openssl x509 -noout -subject -enddate
	)

	# Test expired cert.
	openssl s_client -connect "$host:$port" -purpose sslserver -verify_hostname "$host" -verify_depth 3 -x509_strict -verify_return_error </dev/null >/dev/null 2>&1 ||
		result=2
	# Test near expiration
	openssl s_client -connect "$host:$port" -purpose sslserver -verify_hostname "$host" -verify_depth 3 -attime "$warntime" -x509_strict -verify_return_error </dev/null >/dev/null 2>&1 ||
		result=1

	printf '%s Expire after %s\n' "$subject" "$notAfter"
	return $result
}


checkcerts() {
	local hostport host port attime rc res=0
	local -a errs=() warns=()

	attime=$(date -d "$EXPIRE_WARN" +%s)

	for hostport; do
		host=${hostport%:*}
		port=${hostport##*:}
		rc=0
		checkcert "$host" "$port" "$attime" || rc=$?
		((rc > res)) && res=$rc

		if ((rc > 2)); then
			printf 'ERROR: %s: failed to get remote cert\n' "$hostport"
			continue
		fi

		if ((rc >= 2)); then
			errs+=("$hostport")
		elif ((rc >= 1)); then
			warns+=("$hostport")
		fi
	done


	if [ ${#errs[@]} -gt 0 ]; then
		printf 'ERROR: %i invalid cert(s):\n' ${#errs[@]}
		printf '  %s\n' "${errs[@]}"
	fi
	if [ ${#warns[@]} -gt 0 ]; then
		printf 'WARNING: %i cert(s) expiring in less than %s:\n' ${#warns[@]} "$EXPIRE_WARN"
		printf '  %s\n' "${warns[@]}"
	fi

	return $res
}

checkcerts "${HOSTNAMES[@]}"
