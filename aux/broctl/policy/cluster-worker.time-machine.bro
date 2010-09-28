# $Id: cluster-worker.time-machine.bro 6811 2009-07-06 20:41:10Z robin $
#
# We connect the TM to the manager which relays (and logs) commands so we
# do not propagate the worker's TM logs.

redef TimeMachine::logfile &disable_print_hook;
