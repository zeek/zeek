# Generic TCP connection processing.

@load conn

redef capture_filters += { ["tcp"] = "tcp[13] & 7 != 0" };
# redef capture_filters += { ["tcp"] = "(tcp[13] & 7 != 0) or (ip6[53] & 7 != 0)" };
