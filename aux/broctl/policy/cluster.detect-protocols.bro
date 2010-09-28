# $Id: cluster.detect-protocols.bro 6811 2009-07-06 20:41:10Z robin $

# There are so many HTTP servers out there that this consumes too much memory.
redef ProtocolDetector::suppress_servers = { ANALYZER_HTTP };
