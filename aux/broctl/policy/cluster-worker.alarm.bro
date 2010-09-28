# $Id: cluster-worker.alarm.bro 6811 2009-07-06 20:41:10Z robin $
#
# In the cluster worker node, we forward the NOTICE events to the manager, and all 
# reasonable alarms are NOTICES these days, so there is no need to replicate
# the local node's alarm file to the manager node.  Ergo, we disable remote
# printing on the alarm file.

redef bro_alarm_file &disable_print_hook;
