# $Id:$

# binpac file for SSL analyzer

# split in three parts:
#  - ssl-protocol.pac: describes the SSL protocol messages
#  - ssl-analyzer.pac: contains the SSL analyzer code
#  - ssl-record-layer.pac: describes the SSL record layer

%include binpac.pac
%include bro.pac

analyzer SSL withcontext {
	analyzer : SSLAnalyzer;
	flow : SSLFlow;
};


%include ssl-defs.pac

%include ssl-protocol.pac
%include ssl-analyzer.pac
