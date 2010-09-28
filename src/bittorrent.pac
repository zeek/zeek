# This code contributed to Bro by Nadi Sarrar.

%include binpac.pac
%include bro.pac

%extern{
#define MSGLEN_LIMIT 0x40000
%}

analyzer BitTorrent withcontext {
	connection:	BitTorrent_Conn;
	flow:		BitTorrent_Flow;
};

%include bittorrent-protocol.pac
%include bittorrent-analyzer.pac

