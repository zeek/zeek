%include binpac.pac
%include bro.pac

analyzer SMB withcontext { };

%include smb-protocol.pac
%include smb-mailslot.pac
%include smb-pipe.pac
