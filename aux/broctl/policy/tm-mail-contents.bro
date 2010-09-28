# $Id: tm-mail-contents.bro 6811 2009-07-06 20:41:10Z robin $

@load tm-contents

module TimeMachine;

export {

	# Extracts the contents of the connection from the time-machine
	# and mails it out with the specified subject and body prefix. 
	# Also asks the TM to store a copy of the connection's packets
	# under with given filename prefix. If the mail address is empty,
	# the default is taken.
	
	global mail_contents:
		function(id: conn_id, start: time, filename_prefix: string, 
				 subject: string, body_prefix: string, email: string);
}

type mail_info: record {
	subject: string;
	body: string;
	email: string;
	};

global conns: table[conn_id] of mail_info;

function mail_contents(id: conn_id, start: time, filename_prefix: string, subject: string, body_prefix: string, email: string)
	{
	TimeMachine::save_contents_id(filename_prefix, id, start, F, "mail-contents-save");
		
	local idstr = fmt("%s.%d-%s.%d", id$orig_h, id$orig_p, id$resp_h, id$resp_p);
	local fname = fmt("%s.%s", filename_prefix, idstr);
	TimeMachine::capture_connection_id(fname, id, start, F, "mail-contents-capture");

	body_prefix += fmt("@@@@Time Machine trace: %s@@", fname);
	
	conns[id] = [$subject=subject, $body=body_prefix, $email=email];
	}


event TimeMachine::contents_saved(c: connection, orig_file: string, resp_file: string)
	{
	if ( c$id !in conns )
		return;

	local ci = conns[c$id];
	delete conns[c$id];
	
	when ( (local orig = lookup_addr(c$id$orig_h)) && 
		   (local resp = lookup_addr(c$id$resp_h)) )
		{
		# Set arguments for script.
		local args: table[string] of string;
		args["contents_orig"] = orig_file;
		args["contents_resp"] = resp_file;
		args["orig_h"] = fmt("%s", c$id$orig_h);
		args["resp_h"] = fmt("%s", c$id$resp_h);
		args["orig_name"] = orig;
		args["resp_name"] = resp;
		args["subject"] = ci$subject;
		args["body"] = ci$body;
		args["mail_dest"] = ci$email;
		
		system_env("mail-contents", args);
		}
	}

	
