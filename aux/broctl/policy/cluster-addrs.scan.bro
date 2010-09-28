# $Id: cluster-addrs.scan.bro 6811 2009-07-06 20:41:10Z robin $

# Backscatter.
redef distinct_backscatter_peers &persistent &synchronized;

# Address scans
redef distinct_peers &persistent &synchronized;

# Logins.
redef accounts_tried &persistent &synchronized;

## These tables are used to keep track of whether a threshold has been reached.
redef shut_down_thresh_reached  &persistent &synchronized;
redef rb_idx  &persistent &synchronized;
redef rps_idx  &persistent &synchronized;
redef rops_idx  &persistent &synchronized;
redef rpts_idx  &persistent &synchronized;
redef rat_idx  &persistent &synchronized;
redef rrat_idx  &persistent &synchronized;

