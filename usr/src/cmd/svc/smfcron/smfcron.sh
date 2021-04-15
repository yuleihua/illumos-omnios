#!/usr/bin/ksh -p

# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source. A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.

# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.

# This is a utility that can be used by SMF services to add and remove
# cron jobs as a service is enabled and disabled. The service should call
# this script as its method and have a property_group called 'cronjobs'.
# This property group contains definitions of the required cron jobs, per
# user. If the script is not run as root then it can only modify cron jobs
# for the current user.
#
# For example:
#
#	<property_group name="cronjobs" type="application">
#	    <property name='webservd' type='astring'>
#		<astring_list>
#		    <value_node value='*/5 * * * * touch /tmp/test' />
#		    <value_node value='10-17/2 * * * * rm -f /tmp/test' />
#		</astring_list>
#	    </property>
#	    <property name='root' type='astring'>
#		<astring_list>
#		    <value_node value='0 0 * * * /usr/sbin/logadm' />
#		</astring_list>
#	    </property>
#	</property_group>

. /lib/svc/share/smf_include.sh

if [ -z "$SMF_FMRI" ]; then
	echo "This script can only be invoked by smf(5)"
	exit $SMF_EXIT_ERR_NOSMF
fi

LOCKDIR=/etc/svc/volatile

SMF_USER=`id -un`
if [ -z "$SMF_USER" ]; then
	echo "Cannot determine current user name".
	exit $SMF_EXIT_ERR_FATAL
fi

MARK="block added by $SMF_FMRI"
typeset -A jobs

function fatal {
	typeset ex=$1; shift
	echo "$@"
	exit $ex
}

function cron_lock {
	typeset user="$1"

	[ $SMF_USER = root ] || return

	while ! mkdir $LOCKDIR/smfcron.$user; do
		echo "Failed to acquire lock for $user, retrying..."
		sleep 1
	done
}

function cron_unlock {
	typeset user="$1"

	[ $SMF_USER = root ] || return

	rm -rf $LOCKDIR/smfcron.$user
}

function extract_jobs {
	jobs=()
	svccfg -s "$SMF_FMRI" listprop cronjobs | while read job; do
		[[ "$job" = cronjobs/* ]] || continue
		jobname="${job%% *}"
		jobuser="${jobname#cronjobs/}"
		[ $SMF_USER != root -a $jobuser != $SMF_USER ] &&
		    fatal $SMF_EXIT_ERR_CONFIG \
		    "Cannot add cron jobs for $jobuser" \
		    "when running as $SMF_USER"

		set -f
		i=2
		while :; do
			jobline=`echo $job | cut -d\" -f$i`
			[ -z "$jobline" ] && break
			jobs[$jobuser]+=("$jobline")
			((i += 2))
		done
		set +f
	done
}

function job_block {
	typeset user="$1"

	echo "######## BEGIN $MARK"
	echo "## - to remove these lines, disable the service shown above"
	echo "##"
	for line in "${jobs[$user][@]}"; do
		echo "$line"
	done
	echo "##"
	echo "########   END $MARK"
}

function replace_crontab {
	typeset user="$1"
	typeset file="$2"

	if [ ! -s "$file" ]; then
		# Empty file, remove the crontab
		crontab -r "$user"
	elif [ $SMF_USER = "$user" ]; then
		crontab "$file"
	elif [ $SMF_USER = root ]; then
		crontab -u "$user" "$file"
	else
		fatal $SMF_EXIT_ERR_FATAL "Unhandled case in replace_crontab"
	fi
}

function insert_jobs {
	echo "Inserting cron jobs"
	for user in "${!jobs[@]}"; do
		echo "Processing user $user"
		typeset -x new=`mktemp`
		typeset cur=`mktemp`
		# Generate the cron file block
		job_block $user > $new
		# Extract the existing block
		cron_lock $user
		crontab -l $user | \
		    sed -n "\%BEGIN $MARK%,\%END $MARK%p" > $cur
		if cmp -s $cur $new; then
			echo "   - nothing to do"
		else
			echo "   - updating crontab"
			# Need to add or replace the block
			(
				crontab -l $user | \
				    sed "\%BEGIN $MARK%,\%END $MARK%d"
				cat $new
			) > $cur
			replace_crontab $user $cur
		fi
		cron_unlock $user
		rm -f $cur $new
	done
}

function remove_jobs {
	echo "Removing cron jobs"
	for user in "${!jobs[@]}"; do
		echo "Processing user $user"
		typeset new=`mktemp`
		typeset cur=`mktemp`
		cron_lock $user
		crontab -l $user > $cur
		crontab -l $user | sed "\%BEGIN $MARK%,\%END $MARK%d" > $new
		if cmp -s $cur $new; then
			echo "   - nothing to do"
		else
			echo "   - updating crontab"
			replace_crontab $user $new
		fi
		cron_unlock $user
		rm -f $cur $new
	done
}

extract_jobs

case "$1" in
'refresh')
	# Refresh just validates the configuration via extract_jobs above
	;;

'start')
	insert_jobs
	;;

'stop')
	remove_jobs
	;;
*)
	echo "Usage: $0 { start | stop | refresh }"
	exit 1
	;;
esac

exit $SMF_EXIT_OK

