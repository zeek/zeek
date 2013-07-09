// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#include "BackDoor.h"
#include "Event.h"
#include "Net.h"
#include "analyzer/protocol/tcp/TCP.h"

#include "events.bif.h"

using namespace analyzer::backdoor;

BackDoorEndpoint::BackDoorEndpoint(tcp::TCP_Endpoint* e)
	{
	endp = e;
	is_partial = 0;
	max_top_seq = 0;

	rlogin_checking_done = 0;
	rlogin_string_separator_pos = 0;
	rlogin_num_null = 0;
	rlogin_slash_seen = 0;

	num_pkts = num_8k0_pkts = num_8k4_pkts =
		num_lines = num_normal_lines = num_bytes = num_7bit_ascii = 0;
	}

#define NORMAL_LINE_LENGTH 80

#define TELNET_IAC 255
#define IS_TELNET_NEGOTIATION_CMD(c) ((c) >= 251 && (c) <= 254)

#define DEFAULT_MTU 512

#define RLOGIN_MAX_SIGNATURE_LENGTH 256

void BackDoorEndpoint::FinalCheckForRlogin()
	{
	if ( ! rlogin_checking_done )
		{
		rlogin_checking_done = 1;

		if ( rlogin_num_null > 0 )
			RloginSignatureFound(0);
		}
	}

int BackDoorEndpoint::DataSent(double /* t */, int seq,
				int len, int caplen, const u_char* data,
				const IP_Hdr* /* ip */,
				const struct tcphdr* /* tp */)
	{
	if ( caplen < len )
		len = caplen;

	if ( len <= 0 )
		return 0;

	if ( endp->state == tcp::TCP_ENDPOINT_PARTIAL )
		is_partial = 1;

	int ack = endp->AckSeq() - endp->StartSeq();
	int top_seq = seq + len;

	if ( top_seq <= ack || top_seq <= max_top_seq )
		// There is no new data in this packet.
		return 0;

	if ( rlogin_signature_found )
		CheckForRlogin(seq, len, data);

	if ( telnet_signature_found )
		CheckForTelnet(seq, len, data);

	if ( ssh_signature_found )
		CheckForSSH(seq, len, data);

	if ( ftp_signature_found )
		CheckForFTP(seq, len, data);

	if ( root_backdoor_signature_found )
		CheckForRootBackdoor(seq, len, data);

	if ( napster_signature_found )
		CheckForNapster(seq, len, data);

	if ( gnutella_signature_found )
		CheckForGnutella(seq, len, data);

	if ( kazaa_signature_found )
		CheckForKazaa(seq, len, data);

	if ( http_signature_found || http_proxy_signature_found )
		CheckForHTTP(seq, len, data);

	if ( smtp_signature_found )
		CheckForSMTP(seq, len, data);

	if ( irc_signature_found )
		CheckForIRC(seq, len, data);

	if ( gaobot_signature_found )
		CheckForGaoBot(seq, len, data);

	max_top_seq = top_seq;

	return 1;
	}

RecordVal* BackDoorEndpoint::BuildStats()
	{
	RecordVal* stats = new RecordVal(backdoor_endp_stats);

	stats->Assign(0, new Val(is_partial, TYPE_BOOL));
	stats->Assign(1, new Val(num_pkts, TYPE_COUNT));
	stats->Assign(2, new Val(num_8k0_pkts, TYPE_COUNT));
	stats->Assign(3, new Val(num_8k4_pkts, TYPE_COUNT));
	stats->Assign(4, new Val(num_lines, TYPE_COUNT));
	stats->Assign(5, new Val(num_normal_lines, TYPE_COUNT));
	stats->Assign(6, new Val(num_bytes, TYPE_COUNT));
	stats->Assign(7, new Val(num_7bit_ascii, TYPE_COUNT));

	return stats;
	}

void BackDoorEndpoint::CheckForRlogin(int seq, int len, const u_char* data)
	{
	if ( rlogin_checking_done )
		return;

	// Looking for pattern:
	//	<null>string<null>string<null>string/string<null>
	// where all string's are non-empty 7-bit-ascii string
	//
	// To avoid having to reassemble, we keep testing each byte until
	// one of the following happens:
	//
	//	- A gap in sequence number occurs
	//	- Four null's have been found
	//	- The number of bytes we examined reaches RLOGIN_MAX_SIGNATURE_LENGTH
	//	- An empty or non-7-bit-ascii string is found
	//
	if ( seq == 1 )
		{ // Check if first byte is a NUL.
		if ( data[0] == 0 )
			{
			rlogin_num_null = 1;

			if ( ! endp->IsOrig() )
				{
				RloginSignatureFound(len);
				return;
				}

			rlogin_string_separator_pos = 1;

			++seq;	// move past the byte
			++data;
			--len;
			}
		else
			{
			rlogin_checking_done = 1;
			return;
			}
		}

	if ( seq > max_top_seq && max_top_seq != 0 )
		{ // A gap! Since we don't reassemble things, stop now.
		RloginSignatureFound(0);
		return;
		}

	if ( seq + len <= max_top_seq )
		return;	// nothing new

	if ( seq < max_top_seq )
		{ // trim to just the new data
		int delta = max_top_seq - seq;
		seq += delta;
		data += delta;
		len -= delta;
		}

	// Search for rlogin signature.
	for ( int i = 0; i < len && rlogin_num_null < 4; ++i )
		{
		if ( data[i] == 0 )
			{
			if ( i + seq == rlogin_string_separator_pos + 1 )
				{ // Empty string found.
				rlogin_checking_done = 1;
				return;
				}
			else
				{
				rlogin_string_separator_pos = i + seq;
				++rlogin_num_null;
				}
			}

		else if ( data[i] == '/' )
			{
			if ( rlogin_num_null == 3 )
				{
				if ( i + seq == rlogin_string_separator_pos + 1 )
					{ // Empty terminal type.
					rlogin_checking_done = 1;
					return;
					}

				rlogin_string_separator_pos = i + seq;
				rlogin_slash_seen = 1;
				}
			}

		else if ( data[i] >= 128 )
			{ // Non-7-bit-ascii
			rlogin_checking_done = 1;
			return;
			}
		}

	if ( rlogin_num_null == 4 )
		{
		if ( rlogin_slash_seen )
			RloginSignatureFound(0);
		else
			rlogin_checking_done = 1;

		return;
		}

	if ( seq + len > RLOGIN_MAX_SIGNATURE_LENGTH )
		{ // We've waited for too long
		RloginSignatureFound(0);
		return;
		}
	}

void BackDoorEndpoint::RloginSignatureFound(int len)
	{
	if ( rlogin_checking_done )
		return;

	rlogin_checking_done = 1;

	val_list* vl = new val_list;
	vl->append(endp->TCP()->BuildConnVal());
	vl->append(new Val(endp->IsOrig(), TYPE_BOOL));
	vl->append(new Val(rlogin_num_null, TYPE_COUNT));
	vl->append(new Val(len, TYPE_COUNT));

	endp->TCP()->ConnectionEvent(rlogin_signature_found, vl);
	}

void BackDoorEndpoint::CheckForTelnet(int /* seq */, int len, const u_char* data)
	{
	if ( len >= 3 &&
	     data[0] == TELNET_IAC && IS_TELNET_NEGOTIATION_CMD(data[1]) )
		{
		TelnetSignatureFound(len);
		return;
		}

	// Note, we do the analysis per-packet rather than on the reassembled
	// stream.  This is a lot more efficient as then we don't need to
	// do stream reassembly; but it's potentially less accurate, and
	// subject to evasion.  *But*: backdoor detection is inherently
	// subject to a wide variety of evasion, so allowing this form
	// (which is a pain to exploit) costs little.

	num_bytes += len;

	int last_char = 0;
	int offset = 0;	// where we consider the latest line to have begun
	int option_length = 0; // length of options in a line

	for ( int i = 0; i < len; ++i )
		{
		unsigned int c = data[i];

		if ( c == '\n' && last_char == '\r' )
			{
			// Compress CRLF to just one line termination.
			last_char = c;
			continue;
			}

		if ( c == '\n' || c == '\r' )
			{
			++num_lines;

			if ( i - offset - option_length <= NORMAL_LINE_LENGTH )
				++num_normal_lines;

			option_length = 0;
			offset = i;
			}

		else if ( c == TELNET_IAC )
			{
			++option_length;
			--num_bytes;

			if ( ++i < len )
				{
				unsigned int code = data[i];
				if ( code == TELNET_IAC )
					// Escaped IAC.
					last_char = code;

				else if ( code >= 251 && code <= 254 )
					{ // 3-byte option: ignore next byte
					++i;
					option_length += 2;
					num_bytes -= 2;
					}

				else
					// XXX: We don't deal with sub option for simplicity
					// although we SHOULD!
					{
					++option_length;
					--num_bytes;
					}
				}
			continue;
			}

		else if ( c != 0 && c < 128 )
			++num_7bit_ascii;

		last_char = c;
		}
	}

void BackDoorEndpoint::TelnetSignatureFound(int len)
	{
	val_list* vl = new val_list;
	vl->append(endp->TCP()->BuildConnVal());
	vl->append(new Val(endp->IsOrig(), TYPE_BOOL));
	vl->append(new Val(len, TYPE_COUNT));

	endp->TCP()->ConnectionEvent(telnet_signature_found, vl);
	}

void BackDoorEndpoint::CheckForSSH(int seq, int len, const u_char* data)
	{
	if ( seq == 1 && CheckForString("SSH-", data, len) && len > 4 &&
	     (data[4] == '1' || data[4] == '2') )
		{
		SignatureFound(ssh_signature_found, 1);
		return;
		}

	// Check for length pattern.

	if ( seq < max_top_seq || max_top_seq == 0 )
		// Retransmission involved, or first pkt => size info useless.
		return;

	if ( seq > max_top_seq )
		{ // Estimate number of packets in the sequence gap
		int gap = seq - max_top_seq;
		num_pkts += int((gap + DEFAULT_MTU - 1) / DEFAULT_MTU);
		}

	++num_pkts;

	// According to the spec:
	//	SSH 1.x pkts have size 8k+4
	//	SSH 2.x pkts have size 8k >= 16 (most cipher blocks are 8n)
	if ( len <= 127 )
		switch ( len & 7 ) {
		case 0:
			if ( len >= 16 )
				++num_8k0_pkts;
			break;

		case 4:
			++num_8k4_pkts;
			break;
		}
	else
		{ // len is likely to be some MTU.
		}
	}

void BackDoorEndpoint::CheckForRootBackdoor(int seq, int len, const u_char* data)
	{
	// Check for root backdoor signature: an initial payload of
	// exactly "# ".
	if ( seq == 1 && len == 2 && ! endp->IsOrig() &&
	     data[0] == '#' && data[1] == ' ' )
		SignatureFound(root_backdoor_signature_found);
	}

void BackDoorEndpoint::CheckForFTP(int seq, int len, const u_char* data)
	{
	// Check for FTP signature
	//
	// Currently, the signatures include: "220 ", "220-"
	//
	// For a day's worth of LBNL FTP activity (7,229 connections),
	// the distribution of the code in the first line returned by
	// the server (the lines always began with a code) is:
	//
	//	220: 6685
	//	421: 535
	//	226: 7
	//	426: 1
	//	200: 1
	//
	// The 421's are all "host does not have access" or "timeout" of
	// some form, so it's not big deal with we miss them (if that helps
	// keep down the false positives).

	if ( seq != 1 || endp->IsOrig() || len < 4 )
		return;

	if ( CheckForString("220", data, len) &&
	     (data[3] == ' ' || data[3] == '-') )
		SignatureFound(ftp_signature_found);

	else if ( CheckForString("421", data, len) &&
		  (data[3] == '-' || data[3] == ' ') )
		SignatureFound(ftp_signature_found);
	}

void BackDoorEndpoint::CheckForNapster(int seq, int len, const u_char* data)
	{
	// Check for Napster signature "GETfoobar" or "SENDfoobar" where
	// "foobar" is the Napster handle associated with the request
	// (so pretty much any arbitrary identifier, but sent adjacent
	// to the GET or SEND with no intervening whitespace; but also
	// sent in a separate packet.

	if ( seq != 1 || ! endp->IsOrig() )
		return;

	if ( len == 3 && CheckForString("GET", data, len) )
		// GETfoobar.
		SignatureFound(napster_signature_found);

	else if ( len == 4 && CheckForString("SEND", data, len) )
		// SENDfoobar.
		SignatureFound(napster_signature_found);
	}

void BackDoorEndpoint::CheckForSMTP(int seq, int len, const u_char* data)
	{
	const char* smtp_handshake[] = { "HELO", "EHLO", 0 };

	if ( seq != 1 )
		return;

	if ( CheckForStrings(smtp_handshake, data, len) )
		SignatureFound(smtp_signature_found);
	}

void BackDoorEndpoint::CheckForIRC(int seq, int len, const u_char* data)
	{
	if ( seq != 1 || is_partial )
		return;

	const char* irc_indicator[] = {
		"ERROR", "INVITE", "ISON", "JOIN", "KICK", "NICK",
		"NJOIN", "NOTICE AUTH", "OPER", "PART", "PING", "PONG",
		"PRIVMSG", "SQUERY", "SQUIT", "WHO", 0,
	};

	if ( CheckForStrings(irc_indicator, data, len) )
		SignatureFound(irc_signature_found);
	}

void BackDoorEndpoint::CheckForGnutella(int seq, int len, const u_char* data)
	{
	// After connecting to the server, the connecting client says:
	//
	//		GNUTELLA CONNECT/<version>\n\n
	//
	// The accepting server responds:
	//
	//		GNUTELLA OK\n\n
	//
	// We find checking the first 8 bytes suffices, and that will
	// also catch variants that use something other than "CONNECT".

	if ( seq == 1 && CheckForString("GNUTELLA ", data, len) )
		SignatureFound(gnutella_signature_found);
	}

void BackDoorEndpoint::CheckForGaoBot(int seq, int len, const u_char* data)
	{
	if ( seq == 1 && CheckForString("220 Bot Server (Win32)", data, len) )
		SignatureFound(gaobot_signature_found);
	}

void BackDoorEndpoint::CheckForKazaa(int seq, int len, const u_char* data)
	{
	// *Some*, though not all, KaZaa connections begin with:
	//
	//		GIVE<space>

	if ( seq == 1 && CheckForString("GIVE ", data, len) )
		SignatureFound(kazaa_signature_found);
	}


int is_http_whitespace(const u_char ch)
	{
	return ! isprint(ch) || isspace(ch);
	}

int skip_http_whitespace(const u_char* data, int len, int max)
	{
	int k;
	for ( k = 0; k < len; ++k )
		{
		if ( ! is_http_whitespace(data[k]) )
			break;

		// Here we do not go beyond CR -- this is OK for
		// processing first line of HTTP requests. However, it
		// cannot be used to process multiple-line headers.

		if ( data[k] == '\015' || k == max )
			return -1;
		}

	return k < len ? k : -1;
	}

int is_absolute_url(const u_char* data, int len)
	{
	// Look for '://' in the URL.
	const char* abs_url_sig = "://";
	const char* abs_url_sig_pos = abs_url_sig;

	// Warning: the following code is NOT general for any signature string,
	// but only works for specific strings like "://".

	for ( int pos = 0; pos < len; ++pos )
		{
		if ( *abs_url_sig_pos == '\0' )
			return 1;

		if ( data[pos] == *abs_url_sig_pos )
			++abs_url_sig_pos;

		else
			{
			if ( is_http_whitespace(data[pos]) )
				return 0;

			abs_url_sig_pos = abs_url_sig;
			if ( *abs_url_sig != '\0' &&
			     *abs_url_sig_pos == data[pos] )
				++abs_url_sig_pos;
			}
		}

	return *abs_url_sig_pos == '\0';
	}

void BackDoorEndpoint::CheckForHTTP(int seq, int len, const u_char* data)
	{
	// According to the RFC, we should look for
	// '<method> SP <url> SP HTTP/<version> CR LF'
	// where:
	//
	//	<method> = GET | HEAD | POST
	//
	// (i.e., HTTP 1.1 methods are ignored for now)
	// <version> = 1.0 | 1.1.
	//
	// However, this is probably too restrictive to catch 'non-standard'
	// requests. Instead, we look for certain methods only in the first
	// line of the first packet only.
	//
	// "The method is case-sensitive." -- RFC 2616

	const char* http_method[] = { "GET", "HEAD", "POST", 0 };

	if ( seq != 1 )
		return; // first packet only

	// Pick up the method.
	int pos = skip_http_whitespace (data, len, 0);
	if ( pos < 0 )
		return;

	int method;
	for ( method = 0; http_method[method]; ++method )
		{
		const char* s = http_method[method];
		int i;
		for ( i = pos; i < len; ++i, ++s )
			if ( data[i] != *s )
				break;

		if ( *s == '\0' )
			{
			pos = i;
			break;
			}
		}

	if ( ! http_method[method] )
		return;

	if ( pos >= len || ! is_http_whitespace(data[pos]) )
		return;

	if ( http_signature_found )
		SignatureFound(http_signature_found);

	if ( http_proxy_signature_found )
		{
		const u_char* rest = data + pos;
		int rest_len = len - pos;

		pos = skip_http_whitespace(rest, rest_len, rest_len);

		if ( pos >= 0 )
			CheckForHTTPProxy(seq, rest_len - pos, rest + pos);
		}
	}

void BackDoorEndpoint::CheckForHTTPProxy(int /* seq */, int len,
					const u_char* data)
	{
	// Proxy ONLY accepts absolute URI's: "The absoluteURI form is
	// REQUIRED when the request is being made to a proxy." -- RFC 2616

	if ( is_absolute_url(data, len) )
		SignatureFound(http_proxy_signature_found);
	}


void BackDoorEndpoint::SignatureFound(EventHandlerPtr e, int do_orig)
	{
	val_list* vl = new val_list;
	vl->append(endp->TCP()->BuildConnVal());

	if ( do_orig )
		vl->append(new Val(endp->IsOrig(), TYPE_BOOL));

	endp->TCP()->ConnectionEvent(e, vl);
	}


int BackDoorEndpoint::CheckForStrings(const char** strs,
					const u_char* data, int len)
	{
	for ( ; *strs; ++strs )
		if ( CheckForFullString(*strs, data, len) )
			return 1;

	return 0;
	}

int BackDoorEndpoint::CheckForFullString(const char* str,
					const u_char* data, int len)
	{
	for ( ; len > 0 && *str; --len, ++data, ++str )
		if ( *str != *data )
			return 0;

	// A "full" string means a non-prefix match.
	return *str == 0 && (len == 0 || *data == ' ' || *data == '\t');
	}

int BackDoorEndpoint::CheckForString(const char* str,
					const u_char* data, int len)
	{
	for ( ; len > 0 && *str; --len, ++data, ++str )
		if ( *str != *data )
			return 0;

	return *str == 0;
	}


BackDoor_Analyzer::BackDoor_Analyzer(Connection* c)
: tcp::TCP_ApplicationAnalyzer("BACKDOOR", c)
	{
	orig_endp = resp_endp = 0;

	orig_stream_pos = resp_stream_pos = 1;

	timeout = backdoor_stat_period;
	backoff = backdoor_stat_backoff;

	c->GetTimerMgr()->Add(new BackDoorTimer(network_time + timeout, this));
	}

BackDoor_Analyzer::~BackDoor_Analyzer()
	{
	delete orig_endp;
	delete resp_endp;
	}

void BackDoor_Analyzer::Init()
	{
	tcp::TCP_ApplicationAnalyzer::Init();

	assert(TCP());
	orig_endp = new BackDoorEndpoint(TCP()->Orig());
	resp_endp = new BackDoorEndpoint(TCP()->Resp());
	}

void BackDoor_Analyzer::DeliverPacket(int len, const u_char* data, bool is_orig,
					int seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

	if ( is_orig )
		orig_endp->DataSent(network_time, seq, len, caplen, data, 0, 0);
	else
		resp_endp->DataSent(network_time, seq, len, caplen, data, 0, 0);
	}

void BackDoor_Analyzer::DeliverStream(int len, const u_char* data, bool is_orig)
	{
	Analyzer::DeliverStream(len, data, is_orig);

	if ( is_orig )
		{
		orig_endp->DataSent(network_time, orig_stream_pos,
					len, len, data, 0, 0);
		orig_stream_pos += len;
		}

	else
		{
		resp_endp->DataSent(network_time, resp_stream_pos,
					len, len, data, 0, 0);
		resp_stream_pos += len;
		}
	}

void BackDoor_Analyzer::Done()
	{
	tcp::TCP_ApplicationAnalyzer::Done();

	if ( ! IsFinished() )
		{
		orig_endp->FinalCheckForRlogin();
		resp_endp->FinalCheckForRlogin();

		if ( ! TCP()->Skipping() )
			StatEvent();

		RemoveEvent();
		}

	}

void BackDoor_Analyzer::StatTimer(double t, int is_expire)
	{
	if ( IsFinished() || TCP()->Skipping() )
		return;

	StatEvent();

	if ( ! is_expire )
		{
		timeout *= backoff;
		timer_mgr->Add(new BackDoorTimer(t + timeout, this));
		}
	}

void BackDoor_Analyzer::StatEvent()
	{
	val_list* vl = new val_list;
	vl->append(TCP()->BuildConnVal());
	vl->append(orig_endp->BuildStats());
	vl->append(resp_endp->BuildStats());

	TCP()->ConnectionEvent(backdoor_stats, vl);
	}

void BackDoor_Analyzer::RemoveEvent()
	{
	val_list* vl = new val_list;
	vl->append(TCP()->BuildConnVal());

	TCP()->ConnectionEvent(backdoor_remove_conn, vl);
	}

BackDoorTimer::BackDoorTimer(double t, BackDoor_Analyzer* a)
: Timer(t, TIMER_BACKDOOR)
	{
	analyzer = a;
	// Make sure connection does not expire.
	Ref(a->Conn());
	}

BackDoorTimer::~BackDoorTimer()
	{
	Unref(analyzer->Conn());
	}

void BackDoorTimer::Dispatch(double t, int is_expire)
	{
	analyzer->StatTimer(t, is_expire);
	}
