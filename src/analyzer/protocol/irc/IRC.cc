// See the file "COPYING" in the main distribution directory for copyright.

// An IRC analyzer contributed by Roland Gruber.

#include "zeek/analyzer/protocol/irc/IRC.h"

#include <unordered_set>

#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/irc/events.bif.h"
#include "zeek/analyzer/protocol/zip/ZIP.h"

using namespace std;

namespace zeek::analyzer {

namespace irc {

IRC_Analyzer::IRC_Analyzer(Connection* conn) : analyzer::tcp::TCP_ApplicationAnalyzer("IRC", conn) {
    invalid_msg_count = 0;
    invalid_msg_max_count = 20;
    orig_status = WAIT_FOR_REGISTRATION;
    resp_status = WAIT_FOR_REGISTRATION;
    orig_zip_status = NO_ZIP;
    resp_zip_status = NO_ZIP;
    starttls = false;
    cl_orig = new analyzer::tcp::ContentLine_Analyzer(conn, true, 1000);
    AddSupportAnalyzer(cl_orig);
    cl_resp = new analyzer::tcp::ContentLine_Analyzer(conn, false, 1000);
    AddSupportAnalyzer(cl_resp);
}

void IRC_Analyzer::Done() { analyzer::tcp::TCP_ApplicationAnalyzer::Done(); }

inline void IRC_Analyzer::SkipLeadingWhitespace(string& str) {
    const auto first_char = str.find_first_not_of(' ');
    if ( first_char == string::npos )
        str = "";
    else
        str = str.substr(first_char);
}

bool IRC_Analyzer::IsValidClientCommand(const std::string& command) {
    static const std::unordered_set<std::string_view> validCommands =
        {"ADMIN",   "AWAY",     "CNOTICE", "CPRIVMSG", "CONNECT", "DIE",    "ENCAP",   "ERROR",    "INFO",
         "INVITE",  "ISON",     "JOIN",    "KICK",     "KILL",    "KNOCK",  "LINKS",   "LIST",     "LUSERS",
         "MODE",    "MOTD",     "NAMES",   "NICK",     "NOTICE",  "OPER",   "PART",    "PASS",     "PING",
         "PONG",    "PRIVMSG",  "QUIT",    "REHASH",   "RULES",   "SERVER", "SERVICE", "SERVLIST", "SERVER",
         "SETNAME", "SILENCE",  "SQUERY",  "SQUIT",    "STATS",   "SUMMON", "TIME",    "TOPIC",    "TRACE",
         "USER",    "USERHOST", "USERS",   "VERSION",  "WALLOPS", "WHO",    "WHOIS",   "WHOWAS",   "STARTTLS"};

    return validCommands.find(command) != validCommands.end();
}

void IRC_Analyzer::DeliverStream(int length, const u_char* line, bool orig) {
    static auto irc_join_list = id::find_type<TableType>("irc_join_list");
    static auto irc_join_info = id::find_type<RecordType>("irc_join_info");
    analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(length, line, orig);

    if ( starttls ) {
        ForwardStream(length, line, orig);
        return;
    }

    // check line size
    if ( length > 512 ) {
        if ( AnalyzerConfirmed() )
            Weird("irc_line_size_exceeded");
        return;
    }

    string myline = string((const char*)line, length);
    SkipLeadingWhitespace(myline);

    if ( myline.length() < 3 ) {
        if ( AnalyzerConfirmed() )
            Weird("irc_line_too_short");
        return;
    }

    // Check for prefix.
    string prefix = "";
    if ( myline[0] == ':' ) { // find end of prefix and extract it
        auto pos = myline.find(' ');
        if ( pos == string::npos ) {
            if ( AnalyzerConfirmed() )
                Weird("irc_invalid_line");
            return;
        }

        prefix = myline.substr(1, pos - 1);
        myline = myline.substr(pos + 1); // remove prefix from line
        SkipLeadingWhitespace(myline);
    }

    int code = 0;
    string command = "";

    // Check if line is long enough to include status code or command.
    // (shortest command with optional params is "WHO")
    if ( myline.length() < 3 ) {
        if ( AnalyzerConfirmed() )
            Weird("irc_invalid_line");
        AnalyzerViolation("line too short");
        return;
    }

    // Check if this is a server reply.
    if ( isdigit(myline[0]) ) {
        if ( isdigit(myline[1]) && isdigit(myline[2]) && myline[3] == ' ' ) {
            code = (myline[0] - '0') * 100 + (myline[1] - '0') * 10 + (myline[2] - '0');
            myline = myline.substr(4);
        }
        else {
            if ( AnalyzerConfirmed() )
                Weird("irc_invalid_reply_number");
            AnalyzerViolation("invalid reply number");
            return;
        }
    }
    else { // get command
        auto pos = myline.find(' ');
        // Not all commands require parameters
        if ( pos == string::npos )
            pos = myline.length();

        command = myline.substr(0, pos);
        for ( size_t i = 0; i < command.size(); ++i )
            command[i] = toupper(command[i]);

        // Adjust for the no-parameter case
        if ( pos == myline.length() )
            pos--;

        myline = myline.substr(pos + 1);
        SkipLeadingWhitespace(myline);
    }

    // Extract parameters.
    string params = myline;

    if ( ! AnalyzerConfirmed() && orig && IsValidClientCommand(command) ) {
        AnalyzerConfirmation();
    }

    // special case
    if ( command == "STARTTLS" )
        return;

    // Check for Server2Server - connections with ZIP enabled.
    if ( orig && orig_status == WAIT_FOR_REGISTRATION ) {
        if ( command == "PASS" ) {
            vector<string> p = SplitWords(params, ' ');
            if ( p.size() > 3 && (p[3].find('Z') <= p[3].size() || p[3].find('z') <= p[3].size()) )
                orig_zip_status = ACCEPT_ZIP;
            else
                orig_zip_status = NO_ZIP;
        }

        // We do not check if SERVER command is successful, since
        // the connection will be terminated by the server if
        // authentication fails.
        //
        // (### This seems not quite prudent to me - VP)
        if ( command == "SERVER" && prefix == "" ) {
            orig_status = REGISTERED;
        }
    }

    if ( ! orig && resp_status == WAIT_FOR_REGISTRATION ) {
        if ( command == "PASS" ) {
            vector<string> p = SplitWords(params, ' ');
            if ( p.size() > 3 && (p[3].find('Z') <= p[3].size() || p[3].find('z') <= p[3].size()) )
                resp_zip_status = ACCEPT_ZIP;
            else
                resp_zip_status = NO_ZIP;
        }

        // Again, don't bother checking whether SERVER command
        // is successful.
        if ( command == "SERVER" && prefix == "" )
            resp_status = REGISTERED;
    }

    // Analyze server reply messages.
    if ( code > 0 ) {
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
            case 251: {
                if ( ! irc_network_info )
                    break;

                vector<string> parts = SplitWords(params, ' ');
                int users = 0;
                int services = 0;
                int servers = 0;

                for ( size_t i = 1; i < parts.size(); ++i ) {
                    if ( parts[i] == "users" )
                        users = atoi(parts[i - 1].c_str());
                    else if ( parts[i] == "services" )
                        services = atoi(parts[i - 1].c_str());
                    else if ( parts[i] == "servers" )
                        servers = atoi(parts[i - 1].c_str());
                    // else ###
                }

                EnqueueConnEvent(irc_network_info, ConnVal(), val_mgr->Bool(orig), val_mgr->Int(users),
                                 val_mgr->Int(services), val_mgr->Int(servers));
            } break;

            // List of users in a channel (names command).
            case 353: {
                if ( ! irc_names_info )
                    break;

                vector<string> parts = SplitWords(params, ' ');

                if ( parts.size() < 3 ) {
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

                auto set = make_intrusive<TableVal>(id::string_set);

                for ( auto& part : parts ) {
                    if ( part[0] == '@' )
                        part = part.substr(1);
                    auto idx = make_intrusive<StringVal>(part);
                    set->Assign(std::move(idx), nullptr);
                }

                EnqueueConnEvent(irc_names_info, ConnVal(), val_mgr->Bool(orig),
                                 make_intrusive<StringVal>(type.c_str()), make_intrusive<StringVal>(channel.c_str()),
                                 std::move(set));
            } break;

            // Count of users and services on this server.
            case 255: {
                if ( ! irc_server_info )
                    break;

                vector<string> parts = SplitWords(params, ' ');
                int users = 0;
                int services = 0;
                int servers = 0;

                for ( size_t i = 1; i < parts.size(); ++i ) {
                    if ( parts[i] == "users," || parts[i] == "clients" )
                        users = atoi(parts[i - 1].c_str());
                    else if ( parts[i] == "services" )
                        services = atoi(parts[i - 1].c_str());
                    else if ( parts[i] == "servers" )
                        servers = atoi(parts[i - 1].c_str());
                    // else ###
                }

                EnqueueConnEvent(irc_server_info, ConnVal(), val_mgr->Bool(orig), val_mgr->Int(users),
                                 val_mgr->Int(services), val_mgr->Int(servers));
            } break;

            // Count of channels.
            case 254: {
                if ( ! irc_channel_info )
                    break;

                vector<string> parts = SplitWords(params, ' ');
                int channels = 0;
                for ( size_t i = 1; i < parts.size(); ++i )
                    if ( parts[i] == ":channels" )
                        channels = atoi(parts[i - 1].c_str());

                EnqueueConnEvent(irc_channel_info, ConnVal(), val_mgr->Bool(orig), val_mgr->Int(channels));
            } break;

            // RPL_GLOBALUSERS
            case 266: {
                // FIXME: We should really streamline all this
                // parsing code ...
                if ( ! irc_global_users )
                    break;

                const char* prefix = params.c_str();

                const char* eop = strchr(prefix, ' ');
                if ( ! eop ) {
                    Weird("invalid_irc_global_users_reply");
                    break;
                }

                const char* msg = strchr(++eop, ':');
                if ( ! msg ) {
                    Weird("invalid_irc_global_users_reply");
                    break;
                }

                EnqueueConnEvent(irc_global_users, ConnVal(), val_mgr->Bool(orig),
                                 make_intrusive<StringVal>(eop - prefix, prefix), make_intrusive<StringVal>(++msg));
            } break;

            // WHOIS user reply line.
            case 311: {
                if ( ! irc_whois_user_line )
                    break;

                vector<string> parts = SplitWords(params, ' ');

                if ( parts.size() > 1 )
                    parts.erase(parts.begin());
                if ( parts.size() < 5 ) {
                    Weird("irc_invalid_whois_user_line");
                    return;
                }

                Args vl;
                vl.reserve(6);
                vl.emplace_back(ConnVal());
                vl.emplace_back(val_mgr->Bool(orig));
                vl.emplace_back(make_intrusive<StringVal>(parts[0].c_str()));
                vl.emplace_back(make_intrusive<StringVal>(parts[1].c_str()));
                vl.emplace_back(make_intrusive<StringVal>(parts[2].c_str()));

                parts.erase(parts.begin(), parts.begin() + 4);

                string real_name = parts[0];
                for ( size_t i = 1; i < parts.size(); ++i )
                    real_name = real_name + " " + parts[i];

                if ( real_name[0] == ':' )
                    real_name = real_name.substr(1);

                vl.emplace_back(make_intrusive<StringVal>(real_name.c_str()));

                EnqueueConnEvent(irc_whois_user_line, std::move(vl));
            } break;

            // WHOIS operator reply line.
            case 313: {
                if ( ! irc_whois_operator_line )
                    break;

                vector<string> parts = SplitWords(params, ' ');

                if ( parts.size() > 1 )
                    parts.erase(parts.begin());

                if ( parts.size() < 2 ) {
                    Weird("irc_invalid_whois_operator_line");
                    return;
                }

                EnqueueConnEvent(irc_whois_operator_line, ConnVal(), val_mgr->Bool(orig),
                                 make_intrusive<StringVal>(parts[0].c_str()));
            } break;

            // WHOIS channel reply.
            case 319: {
                if ( ! irc_whois_channel_line )
                    break;

                vector<string> parts = SplitWords(params, ' ');
                if ( parts.size() < 2 ) {
                    Weird("irc_invalid_whois_channel_line");
                    return;
                }

                string nick = parts[0];
                // Remove nick name.
                parts.erase(parts.begin());

                if ( parts[0][0] == ':' )
                    parts[0] = parts[0].substr(1);

                auto set = make_intrusive<TableVal>(id::string_set);

                for ( const auto& part : parts ) {
                    auto idx = make_intrusive<StringVal>(part);
                    set->Assign(std::move(idx), nullptr);
                }

                EnqueueConnEvent(irc_whois_channel_line, ConnVal(), val_mgr->Bool(orig),
                                 make_intrusive<StringVal>(nick.c_str()), std::move(set));
            } break;

            // RPL_TOPIC reply.
            case 332: {
                if ( ! irc_channel_topic )
                    break;

                vector<string> parts = SplitWords(params, ' ');
                if ( parts.size() < 4 ) {
                    Weird("irc_invalid_topic_reply");
                    return;
                }

                unsigned int pos = params.find(':');
                if ( pos < params.size() ) {
                    string topic = params.substr(pos + 1);
                    const char* t = topic.c_str();

                    if ( *t == ':' )
                        ++t;

                    EnqueueConnEvent(irc_channel_topic, ConnVal(), val_mgr->Bool(orig),
                                     make_intrusive<StringVal>(parts[1].c_str()), make_intrusive<StringVal>(t));
                }
                else {
                    Weird("irc_invalid_topic_reply");
                    return;
                }
            } break;

            // WHO reply line.
            case 352: {
                if ( ! irc_who_line )
                    break;

                vector<string> parts = SplitWords(params, ' ');
                if ( parts.size() < 9 ) {
                    Weird("irc_invalid_who_line");
                    return;
                }

                if ( parts[2][0] == '~' )
                    parts[2] = parts[2].substr(1);

                if ( parts[7][0] == ':' )
                    parts[7] = parts[7].substr(1);

                EnqueueConnEvent(irc_who_line, ConnVal(), val_mgr->Bool(orig),
                                 make_intrusive<StringVal>(parts[0].c_str()),
                                 make_intrusive<StringVal>(parts[1].c_str()),
                                 make_intrusive<StringVal>(parts[2].c_str()),
                                 make_intrusive<StringVal>(parts[3].c_str()),
                                 make_intrusive<StringVal>(parts[4].c_str()),
                                 make_intrusive<StringVal>(parts[5].c_str()),
                                 make_intrusive<StringVal>(parts[6].c_str()), val_mgr->Int(atoi(parts[7].c_str())),
                                 make_intrusive<StringVal>(parts[8].c_str()));
            } break;

            // Invalid nick name.
            case 431:
            case 432:
            case 433:
            case 436:
                if ( irc_invalid_nick )
                    EnqueueConnEvent(irc_invalid_nick, ConnVal(), val_mgr->Bool(orig));
                break;

            // Operator responses.
            case 381: // User is operator
            case 491: // user is not operator
                if ( irc_oper_response )
                    EnqueueConnEvent(irc_oper_response, ConnVal(), val_mgr->Bool(orig), val_mgr->Bool(code == 381));
                break;

            case 670:
                // StartTLS success reply to StartTLS
                StartTLS();
                break;

            // All other server replies.
            default:
                if ( irc_reply )
                    EnqueueConnEvent(irc_reply, ConnVal(), val_mgr->Bool(orig),
                                     make_intrusive<StringVal>(prefix.c_str()), val_mgr->Count(code),
                                     make_intrusive<StringVal>(params.c_str()));
                break;
        }
        return;
    }

    // Check if command is valid.
    if ( command.size() > 20 ) {
        Weird("irc_invalid_command");
        if ( ++invalid_msg_count > invalid_msg_max_count ) {
            Weird("irc_too_many_invalid");
            AnalyzerViolation("too many long lines");
            return;
        }
        return;
    }

    else if ( (irc_privmsg_message || irc_dcc_message) && command == "PRIVMSG" ) {
        unsigned int pos = params.find(' ');
        if ( pos >= params.size() ) {
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
        if ( message.size() > 3 && message.substr(0, 3) == "DCC" ) {
            if ( message[message.size() - 1] == 1 )
                message = message.substr(0, message.size() - 1);

            vector<string> parts = SplitWords(message, ' ');
            if ( parts.size() < 5 || parts.size() > 6 ) {
                // Turbo DCC extension appends a "T" at the end of handshake.
                if ( ! (parts.size() == 7 && parts[6] == "T") ) {
                    Weird("irc_invalid_dcc_message_format");
                    return;
                }
            }

            // Calculate IP address.
            uint32_t raw_ip = 0;
            for ( size_t i = 0; i < parts[3].size(); ++i ) {
                string s = parts[3].substr(i, 1);
                raw_ip = (10 * raw_ip) + atoi(s.c_str());
            }

            if ( irc_dcc_message )
                EnqueueConnEvent(irc_dcc_message, ConnVal(), val_mgr->Bool(orig),
                                 make_intrusive<StringVal>(prefix.c_str()), make_intrusive<StringVal>(target.c_str()),
                                 make_intrusive<StringVal>(parts[1].c_str()),
                                 make_intrusive<StringVal>(parts[2].c_str()), make_intrusive<AddrVal>(htonl(raw_ip)),
                                 val_mgr->Count(atoi(parts[4].c_str())),
                                 parts.size() >= 6 ? val_mgr->Count(atoi(parts[5].c_str())) : val_mgr->Count(0));
        }

        else {
            if ( irc_privmsg_message )
                EnqueueConnEvent(irc_privmsg_message, ConnVal(), val_mgr->Bool(orig),
                                 make_intrusive<StringVal>(prefix.c_str()), make_intrusive<StringVal>(target.c_str()),
                                 make_intrusive<StringVal>(message.c_str()));
        }
    }

    else if ( irc_notice_message && command == "NOTICE" ) {
        unsigned int pos = params.find(' ');
        if ( pos >= params.size() ) {
            Weird("irc_invalid_notice_message_format");
            return;
        }

        string target = params.substr(0, pos);
        string message = params.substr(pos + 1);
        SkipLeadingWhitespace(message);
        if ( message[0] == ':' )
            message = message.substr(1);

        EnqueueConnEvent(irc_notice_message, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(prefix.c_str()),
                         make_intrusive<StringVal>(target.c_str()), make_intrusive<StringVal>(message.c_str()));
    }

    else if ( irc_squery_message && command == "SQUERY" ) {
        unsigned int pos = params.find(' ');
        if ( pos >= params.size() ) {
            Weird("irc_invalid_squery_message_format");
            return;
        }

        string target = params.substr(0, pos);
        string message = params.substr(pos + 1);
        SkipLeadingWhitespace(message);
        if ( message[0] == ':' )
            message = message.substr(1);

        EnqueueConnEvent(irc_squery_message, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(prefix.c_str()),
                         make_intrusive<StringVal>(target.c_str()), make_intrusive<StringVal>(message.c_str()));
    }

    else if ( irc_user_message && command == "USER" ) {
        // extract username and real name
        vector<string> parts = SplitWords(params, ' ');
        Args vl;
        vl.reserve(6);
        vl.emplace_back(ConnVal());
        vl.emplace_back(val_mgr->Bool(orig));

        if ( parts.size() > 0 )
            vl.emplace_back(make_intrusive<StringVal>(parts[0].c_str()));
        else
            vl.emplace_back(val_mgr->EmptyString());

        if ( parts.size() > 1 )
            vl.emplace_back(make_intrusive<StringVal>(parts[1].c_str()));
        else
            vl.emplace_back(val_mgr->EmptyString());

        if ( parts.size() > 2 )
            vl.emplace_back(make_intrusive<StringVal>(parts[2].c_str()));
        else
            vl.emplace_back(val_mgr->EmptyString());

        string realname;
        for ( size_t i = 3; i < parts.size(); i++ ) {
            realname += parts[i];
            if ( i > 3 )
                realname += " ";
        }

        const char* name = realname.c_str();
        vl.emplace_back(make_intrusive<StringVal>(*name == ':' ? name + 1 : name));

        EnqueueConnEvent(irc_user_message, std::move(vl));
    }

    else if ( irc_oper_message && command == "OPER" ) {
        // extract username and password
        vector<string> parts = SplitWords(params, ' ');
        if ( parts.size() == 2 )
            EnqueueConnEvent(irc_oper_message, ConnVal(), val_mgr->Bool(orig),
                             make_intrusive<StringVal>(parts[0].c_str()), make_intrusive<StringVal>(parts[1].c_str()));

        else
            Weird("irc_invalid_oper_message_format");
    }

    else if ( irc_kick_message && command == "KICK" ) {
        // Extract channels, users and comment.
        vector<string> parts = SplitWords(params, ' ');
        if ( parts.size() <= 1 ) {
            Weird("irc_invalid_kick_message_format");
            return;
        }

        Args vl;
        vl.reserve(6);
        vl.emplace_back(ConnVal());
        vl.emplace_back(val_mgr->Bool(orig));
        vl.emplace_back(make_intrusive<StringVal>(prefix.c_str()));
        vl.emplace_back(make_intrusive<StringVal>(parts[0].c_str()));
        vl.emplace_back(make_intrusive<StringVal>(parts[1].c_str()));

        if ( parts.size() > 2 ) {
            string comment = parts[2];
            for ( size_t i = 3; i < parts.size(); ++i )
                comment += " " + parts[i];

            if ( comment[0] == ':' )
                comment = comment.substr(1);

            vl.emplace_back(make_intrusive<StringVal>(comment.c_str()));
        }
        else
            vl.emplace_back(val_mgr->EmptyString());

        EnqueueConnEvent(irc_kick_message, std::move(vl));
    }

    else if ( irc_join_message && command == "JOIN" ) {
        if ( params[0] == ':' )
            params = params.substr(1);

        vector<string> parts = SplitWords(params, ' ');

        if ( parts.size() < 1 ) {
            Weird("irc_invalid_join_line");
            return;
        }

        string nickname = "";
        if ( prefix.size() > 0 ) {
            unsigned int pos = prefix.find('!');
            if ( pos < prefix.size() )
                nickname = prefix.substr(0, pos);
        }

        auto list = make_intrusive<TableVal>(irc_join_list);

        vector<string> channels = SplitWords(parts[0], ',');
        vector<string> passwords;

        if ( parts.size() > 1 )
            passwords = SplitWords(parts[1], ',');

        string empty_string = "";
        for ( size_t i = 0; i < channels.size(); ++i ) {
            auto info = make_intrusive<RecordVal>(irc_join_info);
            info->Assign(0, nickname);
            info->Assign(1, channels[i]);
            if ( i < passwords.size() )
                info->Assign(2, passwords[i]);
            else
                info->Assign(2, empty_string);
            // User mode.
            info->Assign(3, empty_string);
            list->Assign(std::move(info), nullptr);
        }

        EnqueueConnEvent(irc_join_message, ConnVal(), val_mgr->Bool(orig), std::move(list));
    }

    else if ( irc_join_message && command == "NJOIN" ) {
        vector<string> parts = SplitWords(params, ' ');
        if ( parts.size() != 2 ) {
            Weird("irc_invalid_njoin_line");
            return;
        }

        string channel = parts[0];
        if ( parts[1][0] == ':' )
            parts[1] = parts[1].substr(1);

        vector<string> users = SplitWords(parts[1], ',');
        auto list = make_intrusive<TableVal>(irc_join_list);

        string empty_string = "";

        for ( unsigned int i = 0; i < users.size(); ++i ) {
            auto info = make_intrusive<RecordVal>(irc_join_info);
            string nick = users[i];
            string mode = "none";

            if ( nick[0] == '@' ) {
                if ( nick[1] == '@' ) {
                    nick = nick.substr(2);
                    mode = "creator";
                }
                else {
                    nick = nick.substr(1);
                    mode = "operator";
                }
            }

            else if ( nick[0] == '+' ) {
                nick = nick.substr(1);
                mode = "voice";
            }

            info->Assign(0, nick);
            info->Assign(1, channel);
            // Password:
            info->Assign(2, empty_string);
            // User mode:
            info->Assign(3, mode);
            list->Assign(std::move(info), nullptr);
        }

        EnqueueConnEvent(irc_join_message, ConnVal(), val_mgr->Bool(orig), std::move(list));
    }

    else if ( irc_part_message && command == "PART" ) {
        string channels = params;
        string message = "";
        unsigned int pos = params.find(' ');

        if ( pos < params.size() ) {
            channels = params.substr(0, pos);
            if ( params.size() > pos + 1 ) {
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
        auto set = make_intrusive<TableVal>(id::string_set);

        for ( const auto& channel : channelList ) {
            auto idx = make_intrusive<StringVal>(channel);
            set->Assign(std::move(idx), nullptr);
        }

        EnqueueConnEvent(irc_part_message, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(nick.c_str()),
                         std::move(set), make_intrusive<StringVal>(message.c_str()));
    }

    else if ( irc_quit_message && command == "QUIT" ) {
        string message = params;
        if ( message[0] == ':' )
            message = message.substr(1);

        string nickname = "";
        if ( prefix.size() > 0 ) {
            unsigned int pos = prefix.find('!');
            if ( pos < prefix.size() )
                nickname = prefix.substr(0, pos);
        }

        EnqueueConnEvent(irc_quit_message, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(nickname.c_str()),
                         make_intrusive<StringVal>(message.c_str()));
    }

    else if ( irc_nick_message && command == "NICK" ) {
        string nick = params;
        if ( nick[0] == ':' )
            nick = nick.substr(1);

        EnqueueConnEvent(irc_nick_message, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(prefix.c_str()),
                         make_intrusive<StringVal>(nick.c_str()));
    }

    else if ( irc_who_message && command == "WHO" ) {
        vector<string> parts = SplitWords(params, ' ');
        if ( parts.size() > 2 ) {
            Weird("irc_invalid_who_message_format");
            return;
        }

        bool oper = false;
        if ( parts.size() == 2 && parts[1] == "o" )
            oper = true;

        // Remove ":" from mask.
        if ( parts.size() > 0 && parts[0].size() > 0 && parts[0][0] == ':' )
            parts[0] = parts[0].substr(1);

        EnqueueConnEvent(irc_who_message, ConnVal(), val_mgr->Bool(orig),
                         parts.size() > 0 ? make_intrusive<StringVal>(parts[0].c_str()) : val_mgr->EmptyString(),
                         val_mgr->Bool(oper));
    }

    else if ( irc_whois_message && command == "WHOIS" ) {
        vector<string> parts = SplitWords(params, ' ');
        if ( parts.size() < 1 || parts.size() > 2 ) {
            Weird("irc_invalid_whois_message_format");
            return;
        }

        string server = "";
        string users = "";

        if ( parts.size() == 2 ) {
            server = parts[0];
            users = parts[1];
        }
        else
            users = parts[0];

        EnqueueConnEvent(irc_whois_message, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(server.c_str()),
                         make_intrusive<StringVal>(users.c_str()));
    }

    else if ( irc_error_message && command == "ERROR" ) {
        if ( params[0] == ':' )
            params = params.substr(1);

        EnqueueConnEvent(irc_error_message, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(prefix.c_str()),
                         make_intrusive<StringVal>(params.c_str()));
    }

    else if ( irc_invite_message && command == "INVITE" ) {
        vector<string> parts = SplitWords(params, ' ');
        if ( parts.size() == 2 ) { // remove ":" from channel
            if ( parts[1].size() > 0 && parts[1][0] == ':' )
                parts[1] = parts[1].substr(1);

            EnqueueConnEvent(irc_invite_message, ConnVal(), val_mgr->Bool(orig),
                             make_intrusive<StringVal>(prefix.c_str()), make_intrusive<StringVal>(parts[0].c_str()),
                             make_intrusive<StringVal>(parts[1].c_str()));
        }
        else
            Weird("irc_invalid_invite_message_format");
    }

    else if ( irc_mode_message && command == "MODE" ) {
        if ( params.size() > 0 )
            EnqueueConnEvent(irc_mode_message, ConnVal(), val_mgr->Bool(orig),
                             make_intrusive<StringVal>(prefix.c_str()), make_intrusive<StringVal>(params.c_str()));

        else
            Weird("irc_invalid_mode_message_format");
    }

    else if ( irc_password_message && command == "PASS" ) {
        EnqueueConnEvent(irc_password_message, ConnVal(), val_mgr->Bool(orig),
                         make_intrusive<StringVal>(params.c_str()));
    }

    else if ( irc_squit_message && command == "SQUIT" ) {
        string server = params;
        string message = "";

        unsigned int pos = params.find(' ');
        if ( pos < params.size() ) {
            server = params.substr(0, pos);
            message = params.substr(pos + 1);
            SkipLeadingWhitespace(message);
            if ( message[0] == ':' )
                message = message.substr(1);
        }

        EnqueueConnEvent(irc_squit_message, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(prefix.c_str()),
                         make_intrusive<StringVal>(server.c_str()), make_intrusive<StringVal>(message.c_str()));
    }

    else if ( orig ) {
        if ( irc_request ) {
            EnqueueConnEvent(irc_request, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(prefix.c_str()),
                             make_intrusive<StringVal>(command.c_str()), make_intrusive<StringVal>(params.c_str()));
        }
    }

    else {
        if ( irc_message ) {
            EnqueueConnEvent(irc_message, ConnVal(), val_mgr->Bool(orig), make_intrusive<StringVal>(prefix.c_str()),
                             make_intrusive<StringVal>(command.c_str()), make_intrusive<StringVal>(params.c_str()));
        }
    }

    if ( orig_status == REGISTERED && resp_status == REGISTERED && orig_zip_status == ACCEPT_ZIP &&
         resp_zip_status == ACCEPT_ZIP ) {
        orig_zip_status = ZIP_LOADED;
        resp_zip_status = ZIP_LOADED;
        AddSupportAnalyzer(new analyzer::zip::ZIP_Analyzer(Conn(), true));
        AddSupportAnalyzer(new analyzer::zip::ZIP_Analyzer(Conn(), false));
    }

    return;
}

void IRC_Analyzer::StartTLS() {
    // STARTTLS was successful. Remove support analyzers, add SSL
    // analyzer, and throw event signifying the change.
    starttls = true;

    RemoveSupportAnalyzer(cl_orig);
    RemoveSupportAnalyzer(cl_resp);

    Analyzer* ssl = analyzer_mgr->InstantiateAnalyzer("SSL", Conn());
    if ( ssl )
        AddChildAnalyzer(ssl);

    if ( irc_starttls )
        EnqueueConnEvent(irc_starttls, ConnVal());
}

vector<string> IRC_Analyzer::SplitWords(const string& input, char split) {
    vector<string> words;

    if ( input.empty() )
        return words;

    unsigned int start = 0;
    unsigned int split_pos = 0;

    // Ignore split-characters at the line beginning.
    while ( input[start] == split ) {
        ++start;
        ++split_pos;
    }

    string word = "";
    while ( (split_pos = input.find(split, start)) < input.size() ) {
        word = input.substr(start, split_pos - start);
        if ( word.size() > 0 && word[0] != split )
            words.push_back(word);

        start = split_pos + 1;
    }

    // Add line end if needed.
    if ( start < input.size() ) {
        word = input.substr(start, input.size() - start);
        words.push_back(std::move(word));
    }

    return words;
}

} // namespace irc

namespace file {

void IRC_Data::DeliverStream(int len, const u_char* data, bool orig) {
    // Bytes from originator are acknowledgements
    if ( ! orig )
        File_Analyzer::DeliverStream(len, data, orig);
    else {
        constexpr auto ack_len = sizeof(uint32_t);

        if ( len % ack_len != 0 ) {
            Weird("irc_invalid_dcc_send_ack");
            return;
        }

        if ( irc_dcc_send_ack ) {
            for ( int i = 0; i < len; i += ack_len ) {
                EnqueueConnEvent(irc_dcc_send_ack, ConnVal(),
                                 val_mgr->Count(ntohl(*reinterpret_cast<const uint32_t*>(data + i))));
            }
        }
    }
}

void IRC_Data::Undelivered(uint64_t seq, int len, bool orig) {
    if ( ! orig )
        File_Analyzer::Undelivered(seq, len, orig);
}

} // namespace file

} // namespace zeek::analyzer
