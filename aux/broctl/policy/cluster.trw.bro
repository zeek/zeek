# $Id: cluster.trw.bro 6811 2009-07-06 20:41:10Z robin $

redef TRW::target_false_positive_prob = 0.000001;
redef TRW::failed_locals &write_expire = 15 mins;
redef TRW::successful_locals &write_expire = 15 mins;
redef TRW::num_scanned_locals &write_expire = 15 mins;
redef TRW::lambda &write_expire = 15 mins;
