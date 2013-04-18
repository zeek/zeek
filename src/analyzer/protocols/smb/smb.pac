%include binpac.pac
%include bro.pac

%extern{
#include "events.bif.h"
%}

analyzer SMB withcontext { };

%include smb-protocol.pac
%include smb-mailslot.pac
%include smb-pipe.pac
