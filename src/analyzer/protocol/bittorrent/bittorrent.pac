# This code contributed to Zeek by Nadi Sarrar.

%include binpac.pac
%include zeek.pac

%extern{
#define MSGLEN_LIMIT 0x40000

#include "zeek/analyzer/protocol/bittorrent/events.bif.h"
%}

analyzer BitTorrent withcontext {
	connection:	BitTorrent_Conn;
	flow:		BitTorrent_Flow;
};

%include bittorrent-protocol.pac
%include bittorrent-analyzer.pac
