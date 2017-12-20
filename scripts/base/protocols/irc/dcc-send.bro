##! File extraction and introspection for DCC transfers over IRC.
##!
##! There is a major problem with this script in the cluster context because
##! we might see A send B a message that a DCC connection is to be expected,
##! but that connection will actually be between B and C which could be
##! analyzed on a different worker.
##!

# Example line from IRC server indicating that the DCC SEND is about to start:
#    PRIVMSG my_nick :^ADCC SEND whateverfile.zip 3640061780 1026 41709^A

@load ./main
@load base/utils/files
@load base/frameworks/cluster

module IRC;

export {
	redef record Info += {
		## DCC filename requested.
		dcc_file_name:         string &log &optional;
		## Size of the DCC transfer as indicated by the sender.
		dcc_file_size:         count  &log &optional;
		## Sniffed mime type of the file.
		dcc_mime_type:         string &log &optional;
	};

	## The broker topic name to which expected DCC transfer updates are
	## relayed.
	const dcc_transfer_update_topic = "bro/irc/dcc_transfer_update" &redef;
}

global dcc_expected_transfers: table[addr, port] of Info &read_expire=5mins;

event dcc_transfer_add(host: addr, p: port, info: Info)
	{
	dcc_expected_transfers[host, p] = info;
	Analyzer::schedule_analyzer(0.0.0.0, host, p,
	                            Analyzer::ANALYZER_IRC_DATA, 5 min);
	}

event dcc_transfer_remove(host: addr, p: port)
	{
	delete dcc_expected_transfers[host, p];
	}

event bro_init()
	{
	local lnt = Cluster::local_node_type();

	if ( lnt == Cluster::WORKER )
		Broker::subscribe(dcc_transfer_update_topic);
	}

function log_dcc(f: fa_file)
	{
	if ( ! f?$conns ) return;

	for ( cid in f$conns )
		{
		local c: connection = f$conns[cid];

		if ( [cid$resp_h, cid$resp_p] !in dcc_expected_transfers ) next;

		local irc = dcc_expected_transfers[cid$resp_h, cid$resp_p];

		local tmp = irc$command;
		irc$command = "DCC";
		Log::write(IRC::LOG, irc);
		irc$command = tmp;

		# Delete these values in case another DCC transfer
		# happens during the IRC session.
		delete irc$dcc_file_name;
		delete irc$dcc_file_size;
		delete irc$dcc_mime_type;

		delete dcc_expected_transfers[cid$resp_h, cid$resp_p];
		Cluster::relay_rr(Cluster::proxy_pool, dcc_transfer_update_topic,
		                  dcc_transfer_update_topic, dcc_transfer_remove,
		                  cid$resp_h, cid$resp_p);
		return;
		}
	}

event file_new(f: fa_file) &priority=-5
	{
	if ( f$source == "IRC_DATA" )
		log_dcc(f);
	}

event irc_dcc_message(c: connection, is_orig: bool,
			prefix: string, target: string,
			dcc_type: string, argument: string,
			address: addr, dest_port: count, size: count) &priority=5
	{
	set_session(c);
	if ( dcc_type != "SEND" )
		return;
	c$irc$dcc_file_name = argument;
	c$irc$dcc_file_size = size;
	local p = count_to_port(dest_port, tcp);
	Analyzer::schedule_analyzer(0.0.0.0, address, p, Analyzer::ANALYZER_IRC_DATA, 5 min);
	dcc_expected_transfers[address, p] = c$irc;
	Cluster::relay_rr(Cluster::proxy_pool, dcc_transfer_update_topic,
	                  dcc_transfer_update_topic, dcc_transfer_add,
	                  address, p, c$irc);
	}

event scheduled_analyzer_applied(c: connection, a: Analyzer::Tag) &priority=10
	{
	local id = c$id;
	if ( [id$resp_h, id$resp_p] in dcc_expected_transfers )
		add c$service["irc-dcc-data"];
	}

event connection_state_remove(c: connection) &priority=-5
	{
	if ( [c$id$resp_h, c$id$resp_p] in dcc_expected_transfers )
		{
		delete dcc_expected_transfers[c$id$resp_h, c$id$resp_p];
		Cluster::relay_rr(Cluster::proxy_pool, dcc_transfer_update_topic,
		                  dcc_transfer_update_topic, dcc_transfer_remove,
		                  c$id$resp_h, c$id$resp_p);
		}
	}
