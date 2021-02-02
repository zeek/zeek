%{
#include "zeek/zeek-config.h"
#include <stdio.h>
#include <netinet/in.h>
#include <vector>

#include "zeek/RuleAction.h"
#include "zeek/RuleCondition.h"
#include "zeek/RuleMatcher.h"
#include "zeek/Reporter.h"
#include "zeek/IPAddr.h"
#include "zeek/net_util.h"

using namespace zeek::detail;

extern void begin_PS();
extern void end_PS();

zeek::detail::Rule* current_rule = nullptr;
const char* current_rule_file = nullptr;

static uint8_t ip4_mask_to_len(uint32_t mask)
	{
	if ( mask == 0xffffffff )
	    return 32;

	uint32_t x = ~mask + 1;
	uint8_t len;
	for ( len = 0; len < 32 && (! (x & (1 << len))); ++len );

	return 32 - len;
	}
%}

%token TOK_COMP
%token TOK_DISABLE
%token TOK_DST_IP
%token TOK_DST_PORT
%token TOK_ENABLE
%token TOK_EVAL
%token TOK_EVENT
%token TOK_MIME
%token TOK_HEADER
%token TOK_IDENT
%token TOK_INT
%token TOK_IP
%token TOK_IP6
%token TOK_IP_OPTIONS
%token TOK_IP_OPTION_SYM
%token TOK_IP_PROTO
%token TOK_PATTERN
%token TOK_PATTERN_TYPE
%token TOK_PAYLOAD_SIZE
%token TOK_PROT
%token TOK_REQUIRES_SIGNATURE
%token TOK_REQUIRES_REVERSE_SIGNATURE
%token TOK_SIGNATURE
%token TOK_SAME_IP
%token TOK_SRC_IP
%token TOK_SRC_PORT
%token TOK_TCP_STATE
%token TOK_UDP_STATE
%token TOK_STRING
%token TOK_STATE_SYM
%token TOK_ACTIVE
%token TOK_BOOL
%token TOK_POLICY_SYMBOL

%type <str> TOK_STRING TOK_IDENT TOK_POLICY_SYMBOL TOK_PATTERN pattern string
%type <val> TOK_INT TOK_STATE_SYM TOK_IP_OPTION_SYM TOK_COMP
%type <val> integer ipoption_list state_list opt_strength
%type <rule> rule
%type <bl> TOK_BOOL opt_negate
%type <hdr_test> hdr_expr
%type <range> range rangeopt
%type <vallist> value_list
%type <prefix_val_list> prefix_value_list
%type <mval> TOK_IP value
%type <vallist> ranged_value
%type <prefixval> TOK_IP6 prefix_value
%type <prot> TOK_PROT
%type <ptype> TOK_PATTERN_TYPE

%union {
	zeek::detail::Rule* rule;
	zeek::detail::RuleHdrTest* hdr_test;
	zeek::detail::maskedvalue_list* vallist;
	std::vector<zeek::IPPrefix>* prefix_val_list;
	zeek::IPPrefix* prefixval;

	bool bl;
	int val;
	char* str;
	zeek::detail::MaskedValue mval;
	zeek::detail::RuleHdrTest::Prot prot;
	zeek::detail::Range range;
	zeek::detail::Rule::PatternType ptype;
}

%%

rule_list:
		rule_list rule
			{ zeek::detail::rule_matcher->AddRule($2); }
	|
	;

rule:
		TOK_SIGNATURE TOK_IDENT
			{
			zeek::detail::Location l(current_rule_file, rules_line_number+1, 0, 0, 0);
			current_rule = new zeek::detail::Rule(yylval.str, l);
			}
		'{' rule_attr_list '}'
			{ $$ = current_rule; }
	;

rule_attr_list:
		rule_attr_list rule_attr
	|
	;

rule_attr:
		TOK_DST_IP TOK_COMP prefix_value_list
			{
			current_rule->AddHdrTest(new zeek::detail::RuleHdrTest(
				zeek::detail::RuleHdrTest::IPDst,
				(zeek::detail::RuleHdrTest::Comp) $2, *($3)));
			}

	|	TOK_DST_PORT TOK_COMP value_list
			{ // Works for both TCP and UDP
			current_rule->AddHdrTest(new zeek::detail::RuleHdrTest(
				zeek::detail::RuleHdrTest::TCP, 2, 2,
				(zeek::detail::RuleHdrTest::Comp) $2, $3));
			}

	|	TOK_EVAL { begin_PS(); } TOK_POLICY_SYMBOL { end_PS(); }
			{
			current_rule->AddCondition(new zeek::detail::RuleConditionEval($3));
			}

	|	TOK_HEADER hdr_expr
			{ current_rule->AddHdrTest($2); }

	|	TOK_IP_OPTIONS ipoption_list
			{
			current_rule->AddCondition(
				new zeek::detail::RuleConditionIPOptions($2));
			}

	|	TOK_IP_PROTO TOK_COMP TOK_PROT
			{
			int proto = 0;
			switch ( $3 ) {
			case zeek::detail::RuleHdrTest::ICMP: proto = IPPROTO_ICMP; break;
			case zeek::detail::RuleHdrTest::ICMPv6: proto = IPPROTO_ICMPV6; break;
			// signature matching against outer packet headers of IP-in-IP
			// tunneling not supported, so do a no-op there
			case zeek::detail::RuleHdrTest::IP: proto = 0; break;
			case zeek::detail::RuleHdrTest::IPv6: proto = 0; break;
			case zeek::detail::RuleHdrTest::TCP: proto = IPPROTO_TCP; break;
			case zeek::detail::RuleHdrTest::UDP: proto = IPPROTO_UDP; break;
			default:
				rules_error("internal_error: unknown protocol");
			}

			if ( proto )
				{
				auto* vallist = new zeek::detail::maskedvalue_list;
				auto* val = new zeek::detail::MaskedValue();

				val->val = proto;
				val->mask = 0xffffffff;
				vallist->push_back(val);

				// offset & size params are dummies, actual next proto value in
				// header is retrieved dynamically via IP_Hdr::NextProto()
				current_rule->AddHdrTest(new zeek::detail::RuleHdrTest(
					zeek::detail::RuleHdrTest::NEXT, 0, 0,
					(zeek::detail::RuleHdrTest::Comp) $2, vallist));
				}
			}

	|	TOK_IP_PROTO TOK_COMP value_list
			{
			// offset & size params are dummies, actual next proto value in
			// header is retrieved dynamically via IP_Hdr::NextProto()
			current_rule->AddHdrTest(new zeek::detail::RuleHdrTest(
				zeek::detail::RuleHdrTest::NEXT, 0, 0,
				(zeek::detail::RuleHdrTest::Comp) $2, $3));
			}

	|	TOK_EVENT string
			{ current_rule->AddAction(new zeek::detail::RuleActionEvent($2)); }

	|	TOK_MIME string opt_strength
			{ current_rule->AddAction(new zeek::detail::RuleActionMIME($2, $3)); }

	|	TOK_ENABLE TOK_STRING
			{ current_rule->AddAction(new zeek::detail::RuleActionEnable($2)); }

	|	TOK_DISABLE TOK_STRING
			{ current_rule->AddAction(new zeek::detail::RuleActionDisable($2)); }

	|	TOK_PATTERN_TYPE pattern
			{ current_rule->AddPattern($2, $1); }

	|	TOK_PATTERN_TYPE '[' rangeopt ']' pattern
			{
			if ( $3.offset > 0 )
				zeek::reporter->Warning("Offsets are currently ignored for patterns");
			current_rule->AddPattern($5, $1, 0, $3.len);
			}

	|	TOK_PAYLOAD_SIZE TOK_COMP integer
			{
			current_rule->AddCondition(
				new zeek::detail::RuleConditionPayloadSize($3, (zeek::detail::RuleConditionPayloadSize::Comp) ($2)));
			}

	|	TOK_REQUIRES_SIGNATURE TOK_IDENT
			{ current_rule->AddRequires($2, 0, 0); }

	|	TOK_REQUIRES_SIGNATURE '!' TOK_IDENT
			{ current_rule->AddRequires($3, 0, 1); }

	|	TOK_REQUIRES_REVERSE_SIGNATURE TOK_IDENT
			{ current_rule->AddRequires($2, 1, 0); }

	|	TOK_REQUIRES_REVERSE_SIGNATURE '!' TOK_IDENT
			{ current_rule->AddRequires($3, 1, 1); }

	|	TOK_SAME_IP
			{ current_rule->AddCondition(new zeek::detail::RuleConditionSameIP()); }

	|	TOK_SRC_IP TOK_COMP prefix_value_list
			{
			current_rule->AddHdrTest(new zeek::detail::RuleHdrTest(
				zeek::detail::RuleHdrTest::IPSrc,
				(zeek::detail::RuleHdrTest::Comp) $2, *($3)));
			}

	|	TOK_SRC_PORT TOK_COMP value_list
			{ // Works for both TCP and UDP
			current_rule->AddHdrTest(new zeek::detail::RuleHdrTest(
				zeek::detail::RuleHdrTest::TCP, 0, 2,
				(zeek::detail::RuleHdrTest::Comp) $2, $3));
			}

	|	TOK_TCP_STATE state_list
			{
			current_rule->AddCondition(new zeek::detail::RuleConditionTCPState($2));
			}

	|	TOK_UDP_STATE state_list
			{
			if ( $2 & zeek::detail::RULE_STATE_ESTABLISHED )
				rules_error("'established' is not a valid 'udp-state'");

			current_rule->AddCondition(new zeek::detail::RuleConditionUDPState($2));
			}

	|	TOK_ACTIVE TOK_BOOL
			{ current_rule->SetActiveStatus($2); }
	;

hdr_expr:
		TOK_PROT '[' range ']' '&' integer TOK_COMP value
			{
			auto* vallist = new zeek::detail::maskedvalue_list;
			auto* val = new zeek::detail::MaskedValue();

			val->val = $8.val;
			val->mask = $6;
			vallist->push_back(val);

			$$ = new zeek::detail::RuleHdrTest($1, $3.offset, $3.len,
					(zeek::detail::RuleHdrTest::Comp) $7, vallist);
			}

	|	TOK_PROT '[' range ']' TOK_COMP value_list
			{
			$$ = new zeek::detail::RuleHdrTest($1, $3.offset, $3.len,
						(zeek::detail::RuleHdrTest::Comp) $5, $6);
			}
	;

value_list:
		value_list ',' value
			{ $1->push_back(new zeek::detail::MaskedValue($3)); $$ = $1; }
	|	value_list ',' ranged_value
			{
			int numVals = $3->length();
			for ( int idx = 0; idx < numVals; idx++ )
				{
				zeek::detail::MaskedValue* val = (*$3)[idx];
				$1->push_back(val);
				}
			$$ = $1;
			}
	|	value_list ',' TOK_IDENT
			{ id_to_maskedvallist($3, $1); $$ = $1; }
	|	value
			{
			$$ = new zeek::detail::maskedvalue_list();
			$$->push_back(new zeek::detail::MaskedValue($1));
			}
	|	ranged_value
			{
			$$ = $1;
			}
	|	TOK_IDENT
			{
			$$ = new zeek::detail::maskedvalue_list();
			id_to_maskedvallist($1, $$);
			}
	;

prefix_value_list:
		prefix_value_list ',' prefix_value
			{
			$$ = $1;
			$$->push_back(*($3));
			}
	|	prefix_value_list ',' TOK_IDENT
			{
			$$ = $1;
			id_to_maskedvallist($3, 0, $1);
			}
	|	prefix_value
			{
			$$ = new std::vector<zeek::IPPrefix>();
			$$->push_back(*($1));
			}
	|	TOK_IDENT
			{
			$$ = new std::vector<zeek::IPPrefix>();
			id_to_maskedvallist($1, 0, $$);
			}
	;

prefix_value:
		TOK_IP
			{
			$$ = new zeek::IPPrefix(zeek::IPAddr(IPv4, &($1.val), zeek::IPAddr::Host),
			                        ip4_mask_to_len($1.mask));
			}
	|	TOK_IP6
	;

ranged_value:
		TOK_INT '-' TOK_INT
			{
			$$ = new zeek::detail::maskedvalue_list();
			for ( int val = $1; val <= $3; val++ )
				{
				auto* masked = new zeek::detail::MaskedValue();
				masked->val = val;
				masked->mask = 0xffffffff;
				$$->push_back(masked);
				}
			}
		;

value:
		TOK_INT
			{ $$.val = $1; $$.mask = 0xffffffff; }
	|	TOK_IP
	;

rangeopt:
		range
			{ $$ = $1; }
	|	':' integer
			{ $$.offset = 0; $$.len = $2; }
	|	integer ':'
			{ $$.offset = $1; $$.len = UINT_MAX; }
	;

range:
		integer
			{ $$.offset = $1; $$.len = 1; }
	|	integer ':' integer
			{ $$.offset = $1; $$.len = $3; }
	;

ipoption_list:
		ipoption_list ',' TOK_IP_OPTION_SYM
			{ $$ = $1 | $3; }
	|	TOK_IP_OPTION_SYM
			{ $$ = $1; }
	;

state_list:
		state_list ',' TOK_STATE_SYM
			{ $$ = $1 | $3; }
	|	TOK_STATE_SYM
			{ $$ = $1; }
	;

integer:
		TOK_INT
			{ $$ = $1; }
	|	TOK_IDENT
			{ $$ = id_to_uint($1); }
	;

opt_negate:
		'-'
			{ $$ = true; }
	|
			{ $$ = false; }
	;

opt_strength:
		',' opt_negate TOK_INT
			{ $$ = $2 ? -$3 : $3; }
	|
			{ $$ = 0; }
	;

string:
		TOK_STRING
			{ $$ = $1; }
	|	TOK_IDENT
			{ $$ = id_to_str($1); }
	;

pattern:
		TOK_PATTERN
			{ $$ = $1; }
	|	TOK_IDENT
			{ $$ = id_to_str($1); }
	;

%%

void rules_error(const char* msg)
	{
	zeek::reporter->Error("Error in signature (%s:%d): %s\n",
	                      current_rule_file, rules_line_number+1, msg);
	zeek::detail::rule_matcher->SetParseError();
	}

void rules_error(const char* msg, const char* addl)
	{
	zeek::reporter->Error("Error in signature (%s:%d): %s (%s)\n",
	                      current_rule_file, rules_line_number+1, msg, addl);
	zeek::detail::rule_matcher->SetParseError();
	}

void rules_error(zeek::detail::Rule* r, const char* msg)
	{
	const zeek::detail::Location& l = r->GetLocation();
	zeek::reporter->Error("Error in signature %s (%s:%d): %s\n",
	                      r->ID(), l.filename, l.first_line, msg);
	zeek::detail::rule_matcher->SetParseError();
	}

int rules_wrap(void)
	{
	return 1;
	}
