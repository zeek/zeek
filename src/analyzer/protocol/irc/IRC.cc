// An IRC analyzer contributed by Roland Gruber.

#include <iostream>
#include "IRC.h"
#include "NetVar.h"
#include "Event.h"
#include "analyzer/protocol/zip/ZIP.h"
#include "analyzer/Manager.h"

#include "events.bif.h"

using namespace analyzer::irc;

IRC_Analyzer::IRC_Analyzer(Connection* conn)
: tcp::TCP_ApplicationAnalyzer("IRC", conn)
	{
	invalid_msg_count = 0;
	invalid_msg_max_count = 20;
	orig_status = WAIT_FOR_REGISTRATION;
	resp_status = WAIT_FOR_REGISTRATION;
	orig_zip_status = NO_ZIP;
	resp_zip_status = NO_ZIP;
	starttls = false;
	cl_orig = new tcp::ContentLine_Analyzer(conn, true, 1000);
	AddSupportAnalyzer(cl_orig);
	cl_resp = new tcp::ContentLine_Analyzer(conn, false, 1000);
	AddSupportAnalyzer(cl_resp);
	}

void IRC_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();
	}

inline void IRC_Analyzer::SkipLeadingWhitespace(string& str)
	{
	const auto first_char = str.find_first_not_of(' ');
	if ( first_char == string::npos )
		str = "";
	else
		str = str.substr(first_char);
	}

void IRC_Analyzer::DeliverStream(int length, const u_char* line, bool orig)
	{
	tcp::TCP_ApplicationAnalyzer::DeliverStream(length, line, orig);

	if ( starttls )
		{
		ForwardStream(length, line, orig);
		return;
		}

	// check line size
	if ( length > 512 )
		{
		Weird("irc_line_size_exceeded");
		return;
		}

	string myline = string((const char*) line, length);
	SkipLeadingWhitespace(myline);

	if ( myline.length() < 3 )
		{
		Weird("irc_line_too_short");
		return;
		}

	// Check for prefix.
	string prefix = "";
	if ( myline[0] == ':' )
		{ // find end of prefix and extract it
		auto pos = myline.find(' ');
		if ( pos == string::npos )
			{
			Weird("irc_invalid_line");
			return;
			}

		prefix = myline.substr(1, pos - 1);
		myline = myline.substr(pos + 1);  // remove prefix from line
		SkipLeadingWhitespace(myline);
		}

	if ( orig )
		ProtocolConfirmation();

	int code = 0;
	string command = "";

	// Check if line is long enough to include status code or command.
	// (shortest command with optional params is "WHO")
	if ( myline.length() < 3 )
		{
		Weird("irc_invalid_line");
		ProtocolViolation("line too short");
		return;
		}

	// Check if this is a server reply.
	if ( isdigit(myline[0]) )
		{
		if ( isdigit(myline[1]) && isdigit(myline[2]) &&
		     myline[3] == ' ')
			{
			code = (myline[0] - '0') * 100 +
				(myline[1] - '0') * 10 + (myline[2] - '0');
			myline = myline.substr(4);
			}
		else
			{
			Weird("irc_invalid_reply_number");
			ProtocolViolation("invalid reply number");
			return;
			}
		}
	else
		{ // get command
		auto pos = myline.find(' ');
		// Not all commands require parameters
		if ( pos == string::npos )
			pos = myline.length();

		command = myline.substr(0, pos);
		for ( unsigned int i = 0; i < command.size(); ++i )
			command[i] = toupper(command[i]);

		// Adjust for the no-parameter case
		if ( pos == myline.length() )
			pos--;

		myline = myline.substr(pos + 1);
		SkipLeadingWhitespace(myline);
		}

	// Extract parameters.
	string params = myline;

	// special case
	if ( command == "STARTTLS" )
		return;

	// Check for Server2Server - connections with ZIP enabled.
	if ( orig && orig_status == WAIT_FOR_REGISTRATION )
		{
		if ( command == "PASS" )
			{
			vector<string> p = SplitWords(params,' ');
			if ( p.size() > 3 &&
			     (p[3].find('Z')<=p[3].size() ||
			      p[3].find('z')<=p[3].size()) )
				orig_zip_status = ACCEPT_ZIP;
			else
			        orig_zip_status = NO_ZIP;
			}

		// We do not check if SERVER command is successful, since
		// the connection will be terminated by the server if
		// authentication fails.
		//
		// (### This seems not quite prudent to me - VP)
		if ( command == "SERVER" && prefix == "")
			{
			orig_status = REGISTERED;
			}
		}

	if ( ! orig && resp_status == WAIT_FOR_REGISTRATION )
		{
		if ( command == "PASS" )
			{
			vector<string> p = SplitWords(params,' ');
			if ( p.size() > 3 &&
			     (p[3].find('Z')<=p[3].size() ||
			      p[3].find('z')<=p[3].size()) )
			        resp_zip_status = ACCEPT_ZIP;
			else
			        resp_zip_status = NO_ZIP;

			}

		// Again, don't bother checking whether SERVER command
		// is successful.
		if ( command == "SERVER" && prefix == "")
			resp_status = REGISTERED;
		}

	// Analyze server reply messages.
	if ( code > 0 )
		{
		switch ( code ) {
		/*
		case 1: // RPL_WELCOME
		case 2: // RPL_YOURHOST
		case 3: // RPL_CREATED
		case 4: // RPL_MYINFO
		case 5: // RPL_BOUNCE
		case 252: // number of ops online
		case 253: // number of unknown connections
		case 265: // RPL_LOCALUSERS
		case 312: // whois server reply
		case 315: // end of who list
		case 317: // whois idle reply
		case 318: // end of whois list
		case 366: // end of names list
		case 372: // RPL_MOTD
		case 375: // RPL_MOTDSTART
		case 376: // RPL_ENDOFMOTD
		case 331: // RPL_NOTOPIC
			break;
		*/

		// Count of users, services and servers in whole network.
		case 251:
			if ( ! irc_network_info )
				break;

			{
			vector<string> parts = SplitWords(params, ' ');
			int users = 0;
			int services = 0;
			int servers = 0;

			for ( unsigned int i = 1; i < parts.size(); ++i )
				{
				if ( parts[i] == "users" )
					users = atoi(parts[i-1].c_str());
				else if ( parts[i] == "services" )
					services = atoi(parts[i-1].c_str());
				else if ( parts[i] == "servers" )
					servers = atoi(parts[i-1].c_str());
				// else ###
				}

			ConnectionEventFast(irc_network_info, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				val_mgr->GetInt(users),
				val_mgr->GetInt(services),
				val_mgr->GetInt(servers),
			});
			}
			break;

		// List of users in a channel (names command).
		case 353:
			if ( ! irc_names_info )
				break;

			{
			vector<string> parts = SplitWords(params, ' ');

			if ( parts.size() < 3 )
				{
				Weird("irc_invalid_names_line");
				return;
				}

			// Remove nick name.
			parts.erase(parts.begin());

			string type = parts[0];
			string channel = parts[1];

			// Remove type and channel.
			parts.erase(parts.begin());
			parts.erase(parts.begin());

			if ( parts.size() > 0 && parts[0][0] == ':' )
				parts[0] = parts[0].substr(1);

			TableVal* set = new TableVal(string_set);

			for ( unsigned int i = 0; i < parts.size(); ++i )
				{
				if ( parts[i][0] == '@' )
					parts[i] = parts[i].substr(1);
				Val* idx = new StringVal(parts[i].c_str());
				set->Assign(idx, 0);
				Unref(idx);
				}

			ConnectionEventFast(irc_names_info, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				new StringVal(type.c_str()),
				new StringVal(channel.c_str()),
				set,
			});
			}
			break;

		// Count of users and services on this server.
		case 255:
			if ( ! irc_server_info )
				break;

			{
			vector<string> parts = SplitWords(params, ' ');
			int users = 0;
			int services = 0;
			int servers = 0;

			for ( unsigned int i = 1; i < parts.size(); ++i )
				{
				if ( parts[i] == "users," )
					users = atoi(parts[i-1].c_str());
				else if ( parts[i] == "clients" )
					users = atoi(parts[i-1].c_str());
				else if ( parts[i] == "services" )
					services = atoi(parts[i-1].c_str());
				else if ( parts[i] == "servers" )
					servers = atoi(parts[i-1].c_str());
				// else ###
				}

			ConnectionEventFast(irc_server_info, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				val_mgr->GetInt(users),
				val_mgr->GetInt(services),
				val_mgr->GetInt(servers),
			});
			}
			break;

		// Count of channels.
		case 254:
			if ( ! irc_channel_info )
				break;

			{
			vector<string> parts = SplitWords(params, ' ');
			int channels = 0;
			for ( unsigned int i = 1; i < parts.size(); ++i )
				if ( parts[i] == ":channels" )
					channels = atoi(parts[i - 1].c_str());

			ConnectionEventFast(irc_channel_info, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				val_mgr->GetInt(channels),
			});
			}
			break;

		// RPL_GLOBALUSERS
		case 266:
			{
			// FIXME: We should really streamline all this
			// parsing code ...
			if ( ! irc_global_users )
				break;

			const char* prefix = params.c_str();

			const char* eop = strchr(prefix, ' ');
			if ( ! eop )
				{
				Weird("invalid_irc_global_users_reply");
				break;
				}

			const char *msg = strchr(++eop, ':');
			if ( ! msg )
				{
				Weird("invalid_irc_global_users_reply");
				break;
				}

			ConnectionEventFast(irc_global_users, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				new StringVal(eop - prefix, prefix),
				new StringVal(++msg),
			});
			break;
			}

		// WHOIS user reply line.
		case 311:
			if ( ! irc_whois_user_line )
				break;

			{
			vector<string> parts = SplitWords(params, ' ');

			if ( parts.size() > 1 )
				parts.erase(parts.begin());
			if ( parts.size() < 5 )
				{
				Weird("irc_invalid_whois_user_line");
				return;
				}

			val_list vl(6);
			vl.push_back(BuildConnVal());
			vl.push_back(val_mgr->GetBool(orig));
			vl.push_back(new StringVal(parts[0].c_str()));
			vl.push_back(new StringVal(parts[1].c_str()));
			vl.push_back(new StringVal(parts[2].c_str()));

			parts.erase(parts.begin(), parts.begin() + 4);

			string real_name = parts[0];
			for ( unsigned int i = 1; i < parts.size(); ++i )
				real_name = real_name + " " + parts[i];

			if ( real_name[0] == ':' )
				real_name = real_name.substr(1);

			vl.push_back(new StringVal(real_name.c_str()));

			ConnectionEventFast(irc_whois_user_line, std::move(vl));
			}
			break;

		// WHOIS operator reply line.
		case 313:
			if ( ! irc_whois_operator_line )
				break;

			{
			vector<string> parts = SplitWords(params, ' ');

			if ( parts.size() > 1 )
				parts.erase(parts.begin());

			if ( parts.size() < 2 )
				{
				Weird("irc_invalid_whois_operator_line");
				return;
				}

			ConnectionEventFast(irc_whois_operator_line, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				new StringVal(parts[0].c_str()),
			});
			}
			break;

		// WHOIS channel reply.
		case 319:
			if ( ! irc_whois_channel_line )
				break;

			{
			vector<string> parts = SplitWords(params, ' ');

			// Remove nick name.
			parts.erase(parts.begin());
			if ( parts.size() < 2 )
				{
				Weird("irc_invalid_whois_channel_line");
				return;
				}

			string nick = parts[0];
			parts.erase(parts.begin());

			if ( parts.size() > 0 && parts[0][0] == ':' )
				parts[0] = parts[0].substr(1);

			TableVal* set = new TableVal(string_set);

			for ( unsigned int i = 0; i < parts.size(); ++i )
				{
				Val* idx = new StringVal(parts[i].c_str());
				set->Assign(idx, 0);
				Unref(idx);
				}

			ConnectionEventFast(irc_whois_channel_line, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				new StringVal(nick.c_str()),
				set,
			});
			}
			break;

		// RPL_TOPIC reply.
		case 332:
			{
			if ( ! irc_channel_topic )
				break;

			vector<string> parts = SplitWords(params, ' ');
			if ( parts.size() < 4 )
				{
				Weird("irc_invalid_topic_reply");
				return;
				}

			unsigned int pos = params.find(':');
			if ( pos < params.size() )
				{
				string topic = params.substr(pos + 1);
				const char* t = topic.c_str();

				if ( *t == ':' )
					++t;

				ConnectionEventFast(irc_channel_topic, {
					BuildConnVal(),
					val_mgr->GetBool(orig),
					new StringVal(parts[1].c_str()),
					new StringVal(t),
				});
				}
			else
				{
				Weird("irc_invalid_topic_reply");
				return;
				}
			break;
			}

		// WHO reply line.
		case 352:
			if ( ! irc_who_line )
				break;

			{
			vector<string> parts = SplitWords(params, ' ');
			if ( parts.size() < 9 )
				{
				Weird("irc_invalid_who_line");
				return;
				}

			if ( parts[2][0] == '~' )
				parts[2] = parts[2].substr(1);

			if ( parts[7][0] == ':' )
				parts[7] = parts[7].substr(1);

			ConnectionEventFast(irc_who_line, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				new StringVal(parts[0].c_str()),
				new StringVal(parts[1].c_str()),
				new StringVal(parts[2].c_str()),
				new StringVal(parts[3].c_str()),
				new StringVal(parts[4].c_str()),
				new StringVal(parts[5].c_str()),
				new StringVal(parts[6].c_str()),
				val_mgr->GetInt(atoi(parts[7].c_str())),
				new StringVal(parts[8].c_str()),
			});
			}
			break;

		// Invalid nick name.
		case 431:
		case 432:
		case 433:
		case 436:
			if ( irc_invalid_nick )
				{
				ConnectionEventFast(irc_invalid_nick, {
					BuildConnVal(),
					val_mgr->GetBool(orig),
				});
				}
			break;

		// Operator responses.
		case 381:  // User is operator
		case 491:  // user is not operator
			if ( irc_oper_response )
				{
				ConnectionEventFast(irc_oper_response, {
					BuildConnVal(),
					val_mgr->GetBool(orig),
					val_mgr->GetBool(code == 381),
				});
				}
			break;

		case 670:
			// StartTLS success reply to StartTLS
			StartTLS();
			break;

		// All other server replies.
		default:
			if ( irc_reply )
				ConnectionEventFast(irc_reply, {
					BuildConnVal(),
					val_mgr->GetBool(orig),
					new StringVal(prefix.c_str()),
					val_mgr->GetCount(code),
					new StringVal(params.c_str()),
				});
			break;
		}
		return;
		}

	// Check if command is valid.
	if ( command.size() > 20 )
		{
		Weird("irc_invalid_command");
		if ( ++invalid_msg_count > invalid_msg_max_count )
			{
			Weird("irc_too_many_invalid");
			ProtocolViolation("too many long lines");
			return;
			}
		return;
		}

	else if ( ( irc_privmsg_message || irc_dcc_message ) && command == "PRIVMSG")
		{
		unsigned int pos = params.find(' ');
		if ( pos >= params.size() )
			{
			Weird("irc_invalid_privmsg_message_format");
			return;
			}

		string target = params.substr(0, pos);
		string message = params.substr(pos + 1);
		SkipLeadingWhitespace(message);

		if ( message.size() > 0 && message[0] == ':' )
			message = message.substr(1);
		if ( message.size() > 0 && message[0] == 1 )
			message = message.substr(1); // DCC

		// Check for DCC messages.
		if ( message.size() > 3 && message.substr(0, 3) == "DCC" )
			{
			if ( message.size() > 0 &&
			     message[message.size() - 1] == 1 )
				message = message.substr(0, message.size() - 1);

			vector<string> parts = SplitWords(message, ' ');
			if ( parts.size() < 5 || parts.size() > 6 )
				{
				// Turbo DCC extension appends a "T" at the end of handshake.
				if ( ! (parts.size() == 7 && parts[6] == "T") )
					{
					Weird("irc_invalid_dcc_message_format");
					return;
					}
				}

			// Calculate IP address.
			uint32_t raw_ip = 0;
			for ( unsigned int i = 0; i < parts[3].size(); ++i )
				{
				string s = parts[3].substr(i, 1);
				raw_ip = (10 * raw_ip) + atoi(s.c_str());
				}


			if ( irc_dcc_message )
				ConnectionEventFast(irc_dcc_message, {
					BuildConnVal(),
					val_mgr->GetBool(orig),
					new StringVal(prefix.c_str()),
					new StringVal(target.c_str()),
					new StringVal(parts[1].c_str()),
					new StringVal(parts[2].c_str()),
					new AddrVal(htonl(raw_ip)),
					val_mgr->GetCount(atoi(parts[4].c_str())),
					parts.size() >= 6 ?
						val_mgr->GetCount(atoi(parts[5].c_str())) :
						val_mgr->GetCount(0),
				});
			}

		else
			{
			if ( irc_privmsg_message )
				ConnectionEventFast(irc_privmsg_message, {
					BuildConnVal(),
					val_mgr->GetBool(orig),
					new StringVal(prefix.c_str()),
					new StringVal(target.c_str()),
					new StringVal(message.c_str()),
				});
			}
		}

	else if ( irc_notice_message && command == "NOTICE" )
		{
		unsigned int pos = params.find(' ');
		if ( pos >= params.size() )
			{
			Weird("irc_invalid_notice_message_format");
			return;
			}

		string target = params.substr(0, pos);
		string message = params.substr(pos + 1);
		SkipLeadingWhitespace(message);
		if ( message[0] == ':' )
			message = message.substr(1);

		ConnectionEventFast(irc_notice_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			new StringVal(prefix.c_str()),
			new StringVal(target.c_str()),
			new StringVal(message.c_str()),
		});
		}

	else if ( irc_squery_message && command == "SQUERY" )
		{
		unsigned int pos = params.find(' ');
		if ( pos >= params.size() )
			{
			Weird("irc_invalid_squery_message_format");
			return;
			}

		string target = params.substr(0, pos);
		string message = params.substr(pos + 1);
		SkipLeadingWhitespace(message);
		if ( message[0] == ':' )
			message = message.substr(1);

		ConnectionEventFast(irc_squery_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			new StringVal(prefix.c_str()),
			new StringVal(target.c_str()),
			new StringVal(message.c_str()),
		});
		}

	else if ( irc_user_message && command == "USER" )
		{
		// extract username and real name
		vector<string> parts = SplitWords(params, ' ');
		val_list vl(6);
		vl.push_back(BuildConnVal());
		vl.push_back(val_mgr->GetBool(orig));

		if ( parts.size() > 0 )
			vl.push_back(new StringVal(parts[0].c_str()));
		else vl.push_back(val_mgr->GetEmptyString());

		if ( parts.size() > 1 )
			vl.push_back(new StringVal(parts[1].c_str()));
		else vl.push_back(val_mgr->GetEmptyString());

		if ( parts.size() > 2 )
			vl.push_back(new StringVal(parts[2].c_str()));
		else vl.push_back(val_mgr->GetEmptyString());

		string realname;
		for ( unsigned int i = 3; i < parts.size(); i++ )
			{
			realname += parts[i];
			if ( i > 3 )
				realname += " ";
			}

		const char* name = realname.c_str();
		vl.push_back(new StringVal(*name == ':' ? name + 1 : name));

		ConnectionEventFast(irc_user_message, std::move(vl));
		}

	else if ( irc_oper_message && command == "OPER" )
		{
		// extract username and password
		vector<string> parts = SplitWords(params, ' ');
		if ( parts.size() == 2 )
			{
			ConnectionEventFast(irc_oper_message, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				new StringVal(parts[0].c_str()),
				new StringVal(parts[1].c_str()),
			});
			}

		else
			Weird("irc_invalid_oper_message_format");
		}

	else if ( irc_kick_message && command == "KICK" )
		{
		// Extract channels, users and comment.
		vector<string> parts = SplitWords(params, ' ');
		if ( parts.size() <= 1 )
			{
			Weird("irc_invalid_kick_message_format");
			return;
			}

		val_list vl(6);
		vl.push_back(BuildConnVal());
		vl.push_back(val_mgr->GetBool(orig));
		vl.push_back(new StringVal(prefix.c_str()));
		vl.push_back(new StringVal(parts[0].c_str()));
		vl.push_back(new StringVal(parts[1].c_str()));
		if ( parts.size() > 2 )
			{
			string comment = parts[2];
			for ( unsigned int i = 3; i < parts.size(); ++i )
				comment += " " + parts[i];

			if ( comment[0] == ':' )
				comment = comment.substr(1);

			vl.push_back(new StringVal(comment.c_str()));
			}
		else
			vl.push_back(val_mgr->GetEmptyString());

		ConnectionEventFast(irc_kick_message, std::move(vl));
		}

	else if ( irc_join_message && command == "JOIN" )
		{
		if ( params[0] == ':' )
			params = params.substr(1);

		vector<string> parts = SplitWords(params, ' ');

		if ( parts.size() < 1 )
			{
			Weird("irc_invalid_join_line");
			return;
			}

		string nickname = "";
		if ( prefix.size() > 0 )
			{
			unsigned int pos = prefix.find('!');
			if ( pos < prefix.size() )
				nickname = prefix.substr(0, pos);
			}

		TableVal* list = new TableVal(irc_join_list);

		vector<string> channels = SplitWords(parts[0], ',');
		vector<string> passwords;

		if ( parts.size() > 1 )
			passwords = SplitWords(parts[1], ',');

		string empty_string = "";
		for ( unsigned int i = 0; i < channels.size(); ++i )
			{
			RecordVal* info = new RecordVal(irc_join_info);
			info->Assign(0, new StringVal(nickname.c_str()));
			info->Assign(1, new StringVal(channels[i].c_str()));
			if ( i < passwords.size() )
				info->Assign(2, new StringVal(passwords[i].c_str()));
			else
				info->Assign(2, new StringVal(empty_string.c_str()));
			// User mode.
			info->Assign(3, new StringVal(empty_string.c_str()));
			list->Assign(info, 0);
			Unref(info);
			}

		ConnectionEventFast(irc_join_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			list,
		});
		}

	else if ( irc_join_message && command == "NJOIN" )
		{
		vector<string> parts = SplitWords(params, ' ');
		if ( parts.size() != 2 )
			{
			Weird("irc_invalid_njoin_line");
			return;
			}

		string channel = parts[0];
		if ( parts[1][0] == ':' )
			parts[1] = parts[1].substr(1);

		vector<string> users = SplitWords(parts[1], ',');
		TableVal* list = new TableVal(irc_join_list);

		string empty_string = "";

		for ( unsigned int i = 0; i < users.size(); ++i )
			{
			RecordVal* info = new RecordVal(irc_join_info);
			string nick = users[i];
			string mode = "none";

			if ( nick[0] == '@' )
				{
				if ( nick[1] == '@' )
					{
					nick = nick.substr(2);
					mode = "creator";
					}
				else
					{
					nick = nick.substr(1);
					mode = "operator";
					}
				}

			else if ( nick[0] == '+' )
				{
				nick = nick.substr(1);
				mode = "voice";
				}

			info->Assign(0, new StringVal(nick.c_str()));
			info->Assign(1, new StringVal(channel.c_str()));
			// Password:
			info->Assign(2, new StringVal(empty_string.c_str()));
			// User mode:
			info->Assign(3, new StringVal(mode.c_str()));
			list->Assign(info, 0);
			Unref(info);
			}

		ConnectionEventFast(irc_join_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			list,
		});
		}

	else if ( irc_part_message && command == "PART" )
		{
		string channels = params;
		string message = "";
		unsigned int pos = params.find(' ');

		if ( pos < params.size() )
			{
			channels = params.substr(0, pos);
			if ( params.size() > pos + 1 )
				{
				message = params.substr(pos + 1);
				SkipLeadingWhitespace(message);
				}
			if ( message[0] == ':' )
				message = message.substr(1);
			}

		string nick = prefix;
		pos = nick.find('!');
		if ( pos < nick.size() )
			nick = nick.substr(0, pos);

		vector<string> channelList = SplitWords(channels, ',');
		TableVal* set = new TableVal(string_set);

		for ( unsigned int i = 0; i < channelList.size(); ++i )
			{
			Val* idx = new StringVal(channelList[i].c_str());
			set->Assign(idx, 0);
			Unref(idx);
			}

		ConnectionEventFast(irc_part_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			new StringVal(nick.c_str()),
			set,
			new StringVal(message.c_str()),
		});
		}

	else if ( irc_quit_message && command == "QUIT" )
		{
		string message = params;
		if ( message[0] == ':' )
			message = message.substr(1);

		string nickname = "";
		if ( prefix.size() > 0 )
			{
			unsigned int pos = prefix.find('!');
			if ( pos < prefix.size() )
				nickname = prefix.substr(0, pos);
			}

		ConnectionEventFast(irc_quit_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			new StringVal(nickname.c_str()),
			new StringVal(message.c_str()),
		});
		}

	else if ( irc_nick_message && command == "NICK" )
		{
		string nick = params;
		if ( nick[0] == ':' )
			nick = nick.substr(1);

		ConnectionEventFast(irc_nick_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			new StringVal(prefix.c_str()),
			new StringVal(nick.c_str())
		});
		}

	else if ( irc_who_message && command == "WHO" )
		{
		vector<string> parts = SplitWords(params, ' ');
		if ( parts.size() > 2 )
			{
			Weird("irc_invalid_who_message_format");
			return;
			}

		bool oper = false;
		if ( parts.size() == 2 && parts[1] == "o" )
			oper = true;

		// Remove ":" from mask.
		if ( parts.size() > 0 && parts[0].size() > 0 && parts[0][0] == ':' )
			parts[0] = parts[0].substr(1);

		ConnectionEventFast(irc_who_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			parts.size() > 0 ?
				new StringVal(parts[0].c_str()) :
				val_mgr->GetEmptyString(),
			val_mgr->GetBool(oper),
		});
		}

	else if ( irc_whois_message && command == "WHOIS" )
		{
		vector<string> parts = SplitWords(params, ' ');
		if ( parts.size() < 1 || parts.size() > 2 )
			{
			Weird("irc_invalid_whois_message_format");
			return;
			}

		string server = "";
		string users = "";

		if ( parts.size() == 2 )
			{
			server = parts[0];
			users = parts[1];
			}
		else
			users = parts[0];

		ConnectionEventFast(irc_whois_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			new StringVal(server.c_str()),
			new StringVal(users.c_str()),
		});
		}

	else if ( irc_error_message && command == "ERROR" )
		{
		if ( params[0] == ':' )
			params = params.substr(1);

		ConnectionEventFast(irc_error_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			new StringVal(prefix.c_str()),
			new StringVal(params.c_str()),
		});
		}

	else if ( irc_invite_message && command == "INVITE" )
		{
		vector<string> parts = SplitWords(params, ' ');
		if ( parts.size() == 2 )
			{ // remove ":" from channel
			if ( parts[1].size() > 0 && parts[1][0] == ':' )
				parts[1] = parts[1].substr(1);

			ConnectionEventFast(irc_invite_message, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				new StringVal(prefix.c_str()),
				new StringVal(parts[0].c_str()),
				new StringVal(parts[1].c_str()),
			});
			}
		else
			Weird("irc_invalid_invite_message_format");
		}

	else if ( irc_mode_message && command == "MODE" )
		{
		if ( params.size() > 0 )
			{
			ConnectionEventFast(irc_mode_message, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				new StringVal(prefix.c_str()),
				new StringVal(params.c_str()),
			});
			}

		else
			Weird("irc_invalid_mode_message_format");
		}

	else if ( irc_password_message && command == "PASS" )
		{
		ConnectionEventFast(irc_password_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			new StringVal(params.c_str()),
		});
		}

	else if ( irc_squit_message && command == "SQUIT" )
		{
		string server = params;
		string message = "";

		unsigned int pos = params.find(' ');
		if ( pos < params.size() )
			{
			server = params.substr(0, pos);
			message = params.substr(pos + 1);
			SkipLeadingWhitespace(message);
			if ( message[0] == ':' )
				message = message.substr(1);
			}

		ConnectionEventFast(irc_squit_message, {
			BuildConnVal(),
			val_mgr->GetBool(orig),
			new StringVal(prefix.c_str()),
			new StringVal(server.c_str()),
			new StringVal(message.c_str()),
		});
		}


	else if ( orig )
		{
		if ( irc_request )
			{
			ConnectionEventFast(irc_request, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				new StringVal(prefix.c_str()),
				new StringVal(command.c_str()),
				new StringVal(params.c_str()),
			});
			}
		}

	else
		{
		if ( irc_message )
			{
			ConnectionEventFast(irc_message, {
				BuildConnVal(),
				val_mgr->GetBool(orig),
				new StringVal(prefix.c_str()),
				new StringVal(command.c_str()),
				new StringVal(params.c_str()),
			});
			}
		}

	if ( orig_status == REGISTERED && resp_status == REGISTERED &&
	     orig_zip_status == ACCEPT_ZIP && resp_zip_status == ACCEPT_ZIP )
		{
		orig_zip_status = ZIP_LOADED;
		resp_zip_status = ZIP_LOADED;
		AddSupportAnalyzer(new zip::ZIP_Analyzer(Conn(), true));
		AddSupportAnalyzer(new zip::ZIP_Analyzer(Conn(), false));
		}

	return;
	}

void IRC_Analyzer::StartTLS()
	{
	// STARTTLS was succesful. Remove support analyzers, add SSL
	// analyzer, and throw event signifying the change.
	starttls = true;

	RemoveSupportAnalyzer(cl_orig);
	RemoveSupportAnalyzer(cl_resp);

	Analyzer* ssl = analyzer_mgr->InstantiateAnalyzer("SSL", Conn());
	if ( ssl )
		AddChildAnalyzer(ssl);

	if ( irc_starttls )
		ConnectionEventFast(irc_starttls, {BuildConnVal()});
	}

vector<string> IRC_Analyzer::SplitWords(const string& input, char split)
	{
	vector<string> words;

	if ( input.empty() )
		return words;

	unsigned int start = 0;
	unsigned int split_pos = 0;

	// Ignore split-characters at the line beginning.
	while ( input[start] == split )
		{
		++start;
		++split_pos;
		}

	string word = "";
	while ( (split_pos = input.find(split, start)) < input.size() )
		{
		word = input.substr(start, split_pos - start);
		if ( word.size() > 0 && word[0] != split )
			words.push_back(word);

		start = split_pos + 1;
		}

	// Add line end if needed.
	if ( start < input.size() )
		{
		word = input.substr(start, input.size() - start);
		words.push_back(word);
		}

	return words;
	}
