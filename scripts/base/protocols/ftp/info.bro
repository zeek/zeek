##! Defines data structures for tracking and logging FTP sessions.

module FTP;

@load ./utils-commands

export {

	## This setting changes if passwords used in FTP sessions are
	## captured or not.
	const default_capture_password = F &redef;

	## The expected endpoints of an FTP data channel.
	type ExpectedDataChannel: record {
		## Whether PASV mode is toggled for control channel.
		passive: bool &log;
		## The host that will be initiating the data connection.
		orig_h: addr &log;
		## The host that will be accepting the data connection.
		resp_h: addr &log;
		## The port at which the acceptor is listening for the data
		## connection.
		resp_p: port &log;
	};

	type Info: record {
		## Time when the command was sent.
		ts:               time        &log;
		## Unique ID for the connection.
		uid:              string      &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:               conn_id     &log;
		## User name for the current FTP session.
		user:             string      &log &default="<unknown>";
		## Password for the current FTP session if captured.
		password:         string      &log &optional;
		## Command given by the client.
		command:          string      &log &optional;
		## Argument for the command if one is given.
		arg:              string      &log &optional;

		## Libmagic "sniffed" file type if the command indicates a file
		## transfer.
		mime_type:        string      &log &optional;
		## Size of the file if the command indicates a file transfer.
		file_size:        count       &log &optional;

		## Reply code from the server in response to the command.
		reply_code:       count       &log &optional;
		## Reply message from the server in response to the command.
		reply_msg:        string      &log &optional;

		## Expected FTP data channel.
		data_channel:     ExpectedDataChannel &log &optional;

		## Current working directory that this session is in.  By making
		## the default value '.', we can indicate that unless something
		## more concrete is discovered that the existing but unknown
		## directory is ok to use.
		cwd:                string  &default=".";

		## Command that is currently waiting for a response.
		cmdarg:             CmdArg  &optional;
		## Queue for commands that have been sent but not yet responded
		## to are tracked here.
		pending_commands:   PendingCmds;

		## Indicates if the session is in active or passive mode.
		passive:            bool &default=F;

		## Determines if the password will be captured for this request.
		capture_password:   bool &default=default_capture_password;
	};
}
