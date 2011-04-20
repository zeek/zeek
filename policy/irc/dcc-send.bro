##! File extraction and introspection for DCC transfers over IRC.
##!
##! There is a major problem with this script in the cluster context because
##! we might see A send B a message that a DCC connection is to be expected,
##! but that connection will actually be between B and C which could be 
##! analyzed on a different worker.
##!

## Example line from IRC server indicating that the DCC SEND is about to start:
##    PRIVMSG my_nick :^ADCC SEND whateverfile.zip 3640061780 1026 41709^A

module IRC;

export {
	redef record Info += {
		file_name:    string &optional;
		file_size:    count &optional;
	};
}

global dcc_expected_transfers: table[addr, port] of Info = table();

event file_transferred(c: connection, prefix: string, descr: string,
                       mime_type: string) &priority=5
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in dcc_expected_transfers )
		{
		delete dcc_expected_transfers[id$resp_h, id$resp_p];
		local fh = open("irc-dcc-item");
		set_contents_file(id, CONTENTS_RESP, fh);
		}
	}

event irc_server(c: connection, prefix: string, data: string) &priority=5
	{
	local parts = split_all(data, / /);
	local command = parts[1];
	if ( command == "PRIVMSG" &&
	     /[dD][cC][cC] [sS][eE][nN][dD]/ in data &&
	     |parts| > 12 &&
	     /^[0-9]*$/ == parts[|parts|-4] &&
	     /^[0-9]*$/ == parts[|parts|-2] )
		{
		c$irc$command = "DCC SEND";
		#local ex_h = count_to_v4_addr(to_count(parts[|parts|-4]));
		local ex_p = to_port(to_count(parts[|parts|-2]), tcp);
		c$irc$file_name = parts[|parts|-6];
		c$irc$file_size = to_count(parts[|parts|]);
		#print fmt("file! %s->%s:%d", c$id$orig_h, ex_h, ex_p);
		#expect_connection(c$id$orig_h, ex_h, ex_p, ANALYZER_FILE, 5 min);
		#dcc_expected_transfers[ex_h, ex_p];
		}
	}

