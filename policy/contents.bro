# $Id: contents.bro 47 2004-06-11 07:26:32Z vern $

redef capture_filters += { ["contents"] = "tcp" };

# Keeps track of to which given contents files we've written.
global contents_files: set[string];

event new_connection_contents(c: connection)
	{
	local id = c$id;

	local orig_file =
		fmt("contents.%s.%d-%s.%d",
			id$orig_h, id$orig_p, id$resp_h, id$resp_p);
	local resp_file =
		fmt("contents.%s.%d-%s.%d",
			id$resp_h, id$resp_p, id$orig_h, id$orig_p);

	local orig_f: file;
	local resp_f: file;

	if ( orig_file !in contents_files )
		{
		add contents_files[orig_file];
		orig_f = open(orig_file);
		}
	else
		orig_f = open_for_append(orig_file);

	if ( resp_file !in contents_files )
		{
		add contents_files[resp_file];
		resp_f = open(resp_file);
		}
	else
		resp_f = open_for_append(resp_file);

	set_contents_file(id, CONTENTS_ORIG, orig_f);
	set_contents_file(id, CONTENTS_RESP, resp_f);
	}
