
# $Id: bro.rc-hooks.sh 555 2004-10-22 07:48:30Z rwinslow $

# This script is called by bro.rc at various points during the starting
# and stopping of Bro.  This is presented as an interface into the start
# and stop process so that customizations can be made.  Some simple
# examples are given as defaults.

# As these functions are within the same scope as bro.rc it is possible
# to alter variables that bro.rc needs to run properly.  It is HIGHLY
# recommended that this not be done.  If you do it don't ask why it broke
# because you were already warned.

# These functions should always return true so that bro.rc can complete
# and exit normally.  If these fail to always return unexpected results
# may occur.

# Variables which are intended to be available to this script.
# These are in addition to normal variables in bro.cfg
# LOG_SUFFIX="string"
# PID="integer"
# EXIT_CODE="POSIX exit codes"
# ERROR_MESSAGE="string"
# AUTO_RESTART="t|f"
# START_TIME=`date`
# END_TIME=`date`


post_start_hook() {
	# Exit code should not be set at this point.  If it is there's a problem.
	if [ "${EXIT_CODE}x" = 'x' ]; then
		# example of a successful start
		true
	else
		# example of a failed start
		false
	fi
}


post_exit_hook() {
	if [ "${EXIT_CODE}x" = 'x' ]; then
		# This was set to null on purpose when messages on exit relate to
		# operations encountered by bro.rc and not the bro process itself
		# An example may be notification that bro.rc was sent a TERM
		# so it therefore shutdown the Bro process it was monitoring
		true
	elif [ "${EXIT_CODE}" = '0' ]; then
		# Bro exited normally
		true
	else
		# Bro failed unexpectedly
		false
	fi
	
}

