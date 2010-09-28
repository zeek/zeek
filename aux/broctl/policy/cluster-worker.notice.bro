# $Id: cluster-worker.notice.bro 6811 2009-07-06 20:41:10Z robin $

# We forward the notice events, so don't (also) remote print them.
redef notice_file &disable_print_hook;

