# Code written by Bernhard Ager (2007).

%extern{
#include "net_util.h"
#include "Event.h"
extern RecordType* conn_id;

#include "events.bif.h"
%}

%include bro.pac
%include netflow-analyzer.pac
%include netflow-protocol.pac
