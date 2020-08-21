%{
#include <string.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "RuleMatcher.h"
#include "RuleCondition.h"
#include "IPAddr.h"
#include "util.h"
#include "rule-parse.h"

int rules_line_number = 0;

%}

%x PS

OWS	[ \t]*
WS	[ \t]+
D	[0-9]+
H	[0-9a-fA-F]+
HEX {H}
STRING	\"([^\n\"]|\\\")*\"
IDCOMPONENT [a-zA-Z_][0-9a-zA-Z_-]*
ID	{IDCOMPONENT}(::{IDCOMPONENT})*
IP6	("["({HEX}:){7}{HEX}"]")|("["0x{HEX}({HEX}|:)*"::"({HEX}|:)*"]")|("["({HEX}|:)*"::"({HEX}|:)*"]")|("["({HEX}|:)*"::"({HEX}|:)*({D}"."){3}{D}"]")
RE	\/(\\\/)?([^/]|[^\\]\\\/)*\/i?
META	\.[^ \t]+{WS}[^\n]+
PIDCOMPONENT [A-Za-z_][A-Za-z_0-9]*
PID  {PIDCOMPONENT}(::{PIDCOMPONENT})*

%option nounput nodefault

%%

<*>{
	#.*	/* eat comments */
	{WS}	/* eat white space */
	{META}	/* eat any meta-data/comments */
	\n	++rules_line_number;
}

{IP6}	{
	rules_lval.prefixval = new zeek::IPPrefix(zeek::IPAddr(zeek::util::detail::extract_ip(yytext)), 128, true);
	return TOK_IP6;
	}

{IP6}{OWS}"/"{OWS}{D}	{
	int len = 0;
	std::string ip = zeek::util::detail::extract_ip_and_len(yytext, &len);
	rules_lval.prefixval = new zeek::IPPrefix(zeek::IPAddr(ip), len, true);
	return TOK_IP6;
	}

[!\]\[{}&:,-]	return rules_text[0];

"<="	{ rules_lval.val = zeek::detail::RuleHdrTest::LE; return TOK_COMP; }
">="	{ rules_lval.val = zeek::detail::RuleHdrTest::GE; return TOK_COMP; }
"<"	{ rules_lval.val = zeek::detail::RuleHdrTest::LT; return TOK_COMP; }
">"	{ rules_lval.val = zeek::detail::RuleHdrTest::GT; return TOK_COMP; }
"="	{ rules_lval.val = zeek::detail::RuleHdrTest::EQ; return TOK_COMP; }
"=="	{ rules_lval.val = zeek::detail::RuleHdrTest::EQ; return TOK_COMP; }
"!="	{ rules_lval.val = zeek::detail::RuleHdrTest::NE; return TOK_COMP; }

ip	{ rules_lval.val = zeek::detail::RuleHdrTest::IP; return TOK_PROT; }
ip6	{ rules_lval.val = zeek::detail::RuleHdrTest::IPv6; return TOK_PROT; }
icmp	{ rules_lval.val = zeek::detail::RuleHdrTest::ICMP; return TOK_PROT; }
icmp6	{ rules_lval.val = zeek::detail::RuleHdrTest::ICMPv6; return TOK_PROT; }
tcp	{ rules_lval.val = zeek::detail::RuleHdrTest::TCP; return TOK_PROT; }
udp	{ rules_lval.val = zeek::detail::RuleHdrTest::UDP; return TOK_PROT; }

true	{ rules_lval.val = true; return TOK_BOOL; }
false	{ rules_lval.val = false; return TOK_BOOL; }

established	{
		rules_lval.val = zeek::detail::RuleConditionTCPState::STATE_ESTABLISHED;
		return TOK_TCP_STATE_SYM;
		}

originator	{
		rules_lval.val = zeek::detail::RuleConditionTCPState::STATE_ORIG;
		return TOK_TCP_STATE_SYM;
		}

responder	{
		rules_lval.val = zeek::detail::RuleConditionTCPState::STATE_RESP;
		return TOK_TCP_STATE_SYM;
		}

stateless	{
		rules_lval.val = zeek::detail::RuleConditionTCPState::STATE_STATELESS;
		return TOK_TCP_STATE_SYM;
		}

lsrr		{
		rules_lval.val = zeek::detail::RuleConditionIPOptions::OPT_LSRR;
		return TOK_IP_OPTION_SYM;
		}

lsrre		{
		rules_lval.val = zeek::detail::RuleConditionIPOptions::OPT_LSRRE;
		return TOK_IP_OPTION_SYM;
		}

rr		{
		rules_lval.val = zeek::detail::RuleConditionIPOptions::OPT_RR;
		return TOK_IP_OPTION_SYM;
		}

ssrr		{
		rules_lval.val = zeek::detail::RuleConditionIPOptions::OPT_SSRR;
		return TOK_IP_OPTION_SYM;
		}

disable	return TOK_DISABLE;
dst-ip		return TOK_DST_IP;
dst-port	return TOK_DST_PORT;
enable		return TOK_ENABLE;
eval		return TOK_EVAL;
event		return TOK_EVENT;
file-mime	return TOK_MIME;
header		return TOK_HEADER;
ip-options	return TOK_IP_OPTIONS;
ip-proto	return TOK_IP_PROTO;
payload-size	return TOK_PAYLOAD_SIZE;
requires-signature	return TOK_REQUIRES_SIGNATURE;
requires-reverse-signature	return TOK_REQUIRES_REVERSE_SIGNATURE;
signature	return TOK_SIGNATURE;
same-ip		return TOK_SAME_IP;
src-ip		return TOK_SRC_IP;
src-port	return TOK_SRC_PORT;
tcp-state	return TOK_TCP_STATE;
active		return TOK_ACTIVE;

file-magic { rules_lval.val = zeek::detail::Rule::FILE_MAGIC; return TOK_PATTERN_TYPE; }
payload	{ rules_lval.val = zeek::detail::Rule::PAYLOAD; return TOK_PATTERN_TYPE; }
http-request	{ rules_lval.val = zeek::detail::Rule::HTTP_REQUEST; return TOK_PATTERN_TYPE; }
http-request-body	{ rules_lval.val = zeek::detail::Rule::HTTP_REQUEST_BODY; return TOK_PATTERN_TYPE; }
http-reply-body	{ rules_lval.val = zeek::detail::Rule::HTTP_REPLY_BODY; return TOK_PATTERN_TYPE; }
http-body	{ rules_lval.val = zeek::detail::Rule::HTTP_REPLY_BODY; return TOK_PATTERN_TYPE; }
http-request-header	{ rules_lval.val = zeek::detail::Rule::HTTP_REQUEST_HEADER; return TOK_PATTERN_TYPE; }
http-reply-header	{ rules_lval.val = zeek::detail::Rule::HTTP_REPLY_HEADER; return TOK_PATTERN_TYPE; }
http	{ rules_lval.val = zeek::detail::Rule::HTTP_REQUEST; return TOK_PATTERN_TYPE; }

ftp	{ rules_lval.val = zeek::detail::Rule::FTP; return TOK_PATTERN_TYPE; }
finger	{ rules_lval.val = zeek::detail::Rule::FINGER; return TOK_PATTERN_TYPE; }

{D}("."{D}){3}{OWS}"/"{OWS}{D}	{
	char* s = strchr(yytext, '/');
	*s++ = '\0';

	rules_lval.mval.mask = ~((1 << (32 - atoi(s))) - 1);
	rules_lval.mval.val = ntohl(inet_addr(yytext)) & rules_lval.mval.mask;

	return TOK_IP;
	}

{D}("."{D}){3}	{
	rules_lval.mval.val = ntohl(inet_addr(yytext));
	rules_lval.mval.mask = 0xffffffff;
	return TOK_IP;
	}

{D}	{
	rules_lval.val = (uint32_t) atoi(yytext);
	return TOK_INT;
	}

0x{H}	{
	rules_lval.val = (uint32_t) strtol(yytext, 0, 16);
	return TOK_INT;
	}


{STRING}	{
	*(yytext + strlen(yytext) - 1) = '\0';
	rules_lval.str = yytext + 1;
	return TOK_STRING;
	}

{ID}	{
	rules_lval.str = yytext;
	return TOK_IDENT;
	}

<PS>{PID}	{
	rules_lval.str = yytext;
	return TOK_POLICY_SYMBOL;
	}

{RE}	{
	auto len = strlen(yytext);

	if ( yytext[len - 1] == 'i' )
		{
		*(yytext + len - 2) = '\0';
		const char fmt[] = "(?i:%s)";
		int n = len + strlen(fmt);
		char* s = new char[n + 5 /* slop */];
		snprintf(s, n + 5, fmt, yytext + 1);
		rules_lval.str = s;
		}
	else
		{
		*(yytext + len - 1) = '\0';
		rules_lval.str = yytext + 1;
		}

	return TOK_PATTERN;
	}

<*>.	rules_error("unrecognized character in input", yytext);

%%

// We're about to parse a Bro policy-layer symbol.
void begin_PS()
	{
	BEGIN(PS);
	}

void end_PS()
	{
	BEGIN(INITIAL);
	}
