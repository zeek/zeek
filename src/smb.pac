# $Id: smb.pac 3929 2007-01-14 00:37:59Z vern $

%include binpac.pac
%include bro.pac

analyzer SMB withcontext { };

%include smb-protocol.pac
%include smb-mailslot.pac
%include smb-pipe.pac
