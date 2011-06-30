# $Id:$
#
# Provides a function that requests a particular connection from the
# Time Machine and stores the subsequent reassembled payload into a
# local file.

@load time-machine

module TimeMachine;

export {
	global save_contents:
		function(filename_prefix: string, c: connection,
				in_mem: bool, descr: string);

	global save_contents_id:
		function(filename_prefix: string, id: conn_id, start: time,
				in_mem: bool, descr: string);

	# Raised when contents have been fully saved.
	global contents_saved:
		event(c: connection, orig_file: string, resp_file: string);

	const contents_dir = "tm-contents" &redef;
	}

# Table associating TM tag with filename.
global requested_conns: table[string] of string;

type fnames: record {
	orig: string;
	resp: string;
	orig_f: file;
	resp_f: file;
	};

global external_conns: table[conn_id] of fnames;

function save_contents(filename_prefix: string, c: connection,
			in_mem: bool, descr: string)
	{
	if ( is_external_connection(c) )
		return;

	save_contents_id(filename_prefix, c$id, c$start_time, in_mem, descr);
	}

function save_contents_id(filename_prefix: string, id: conn_id, start: time,
				in_mem: bool, descr: string)
	{
	TimeMachine::suspend_cut_off_id(id, descr);
	local qtag = TimeMachine::request_connection_id(id, start, in_mem, descr);
	if ( qtag == "" )
		return;

	requested_conns[qtag] = filename_prefix;
	}

event connection_external(c: connection, tag: string)
	{
	if ( tag !in requested_conns )
		return;

	local fn = requested_conns[tag];
	local id = c$id;
	local idstr = fmt("%s.%d-%s.%d", id$orig_h, id$orig_p, id$resp_h, id$resp_p);

	local orig_fn = fmt("%s/%s.%s.orig.dat", contents_dir, fn, idstr);
	local resp_fn = fmt("%s/%s.%s.resp.dat", contents_dir, fn, idstr);
	local orig_f = open(orig_fn);
	local resp_f = open(resp_fn);

	set_contents_file(c$id, CONTENTS_ORIG, orig_f);
	set_contents_file(c$id, CONTENTS_RESP, resp_f);

	delete requested_conns[tag];
	external_conns[c$id] =
		[$orig=orig_fn, $resp=resp_fn, $orig_f=orig_f, $resp_f=resp_f];
	}

event delayed_contents_saved(c: connection, orig_file: string, resp_file: string)
	{
	schedule 2 min { TimeMachine::contents_saved(c, orig_file, resp_file) };
	}

event connection_state_remove(c: connection)
	{
	if ( ! is_external_connection(c) )
		return;

	if ( c$id !in external_conns )
		return;

	local fn = external_conns[c$id];

	close(fn$orig_f);
	close(fn$resp_f);

	# FIXME: We delay this a bit as there seems to be some race-condition
	# with the file's data being flushed to disk.  Not sure why, though.
	# However, we need to delay indirectly through another event to
	# install it into the global timer manager.
	event delayed_contents_saved(c, fn$orig, fn$resp);

	delete external_conns[c$id];
	}

event bro_init()
	{
	mkdir(contents_dir);
	}
