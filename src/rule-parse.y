%{
#include <stdio.h>
#include <netinet/in.h>
#include <vector>
#include "zeek-config.h"
#include "RuleMatcher.h"
#include "Reporter.h"
#include "IPAddr.h"
#include "net_util.h"

extern void begin_PS();
extern void end_PS();

Rule* current_rule = 0;
const char* current_rule_file = 0;

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
%token TOK_STRING
%token TOK_TCP_STATE_SYM
%token TOK_ACTIVE
%token TOK_BOOL
%token TOK_POLICY_SYMBOL

%type <str> TOK_STRING TOK_IDENT TOK_POLICY_SYMBOL TOK_PATTERN pattern string
%type <val> TOK_INT TOK_TCP_STATE_SYM TOK_IP_OPTION_SYM TOK_COMP
%type <val> integer ipoption_list tcpstate_list opt_strength
%type <rule> rule
%type <bl> TOK_BOOL opt_negate
%type <hdr_test> hdr_expr
%type <range> range rangeopt
%type <vallist> value_list
%type <prefix_val_list> prefix_value_list
%type <mval> TOK_IP value
%type <prefixval> TOK_IP6 prefix_value
%type <prot> TOK_PROT
%type <ptype> TOK_PATTERN_TYPE

%union {
	Rule* rule;
	RuleHdrTest* hdr_test;
	maskedvalue_list* vallist;
	vector<IPPrefix>* prefix_val_list;
	IPPrefix* prefixval;

	bool bl;
	int val;
	char* str;
	MaskedValue mval;
	RuleHdrTest::Prot prot;
	Range range;
	Rule::PatternType ptype;
}

%%

rule_list:
		rule_list rule
			{ rule_matcher->AddRule($2); }
	|
	;

rule:
		TOK_SIGNATURE TOK_IDENT
			{
			Location l(current_rule_file, rules_line_number+1, 0, 0, 0);
			current_rule = new Rule(yylval.str, l);
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
			current_rule->AddHdrTest(new RuleHdrTest(
				RuleHdrTest::IPDst,
				(RuleHdrTest::Comp) $2, *($3)));
			}

	|	TOK_DST_PORT TOK_COMP value_list
			{ // Works for both TCP and UDP
			current_rule->AddHdrTest(new RuleHdrTest(
				RuleHdrTest::TCP, 2, 2,
				(RuleHdrTest::Comp) $2, $3));
			}

	|	TOK_EVAL { begin_PS(); } TOK_POLICY_SYMBOL { end_PS(); }
			{
			current_rule->AddCondition(new RuleConditionEval($3));
			}

	|	TOK_HEADER hdr_expr
			{ current_rule->AddHdrTest($2); }

	|	TOK_IP_OPTIONS ipoption_list
			{
			current_rule->AddCondition(
				new RuleConditionIPOptions($2));
			}

	|	TOK_IP_PROTO TOK_COMP TOK_PROT
			{
			int proto = 0;
			switch ( $3 ) {
			case RuleHdrTest::ICMP: proto = IPPROTO_ICMP; break;
			case RuleHdrTest::ICMPv6: proto = IPPROTO_ICMPV6; break;
			// signature matching against outer packet headers of IP-in-IP
			// tunneling not supported, so do a no-op there
			case RuleHdrTest::IP: proto = 0; break;
			case RuleHdrTest::IPv6: proto = 0; break;
			case RuleHdrTest::TCP: proto = IPPROTO_TCP; break;
			case RuleHdrTest::UDP: proto = IPPROTO_UDP; break;
			default:
				rules_error("internal_error: unknown protocol");
			}

			if ( proto )
				{
				maskedvalue_list* vallist = new maskedvalue_list;
				MaskedValue* val = new MaskedValue();

				val->val = proto;
				val->mask = 0xffffffff;
				vallist->append(val);

				// offset & size params are dummies, actual next proto value in
				// header is retrieved dynamically via IP_Hdr::NextProto()
				current_rule->AddHdrTest(new RuleHdrTest(
					RuleHdrTest::NEXT, 0, 0,
					(RuleHdrTest::Comp) $2, vallist));
				}
			}

	|	TOK_IP_PROTO TOK_COMP value_list
			{
			// offset & size params are dummies, actual next proto value in
			// header is retrieved dynamically via IP_Hdr::NextProto()
			current_rule->AddHdrTest(new RuleHdrTest(
				RuleHdrTest::NEXT, 0, 0,
				(RuleHdrTest::Comp) $2, $3));
			}

	|	TOK_EVENT string
			{ current_rule->AddAction(new RuleActionEvent($2)); }

	|	TOK_MIME string opt_strength
			{ current_rule->AddAction(new RuleActionMIME($2, $3)); }

	|	TOK_ENABLE TOK_STRING
			{ current_rule->AddAction(new RuleActionEnable($2)); }

	|	TOK_DISABLE TOK_STRING
			{ current_rule->AddAction(new RuleActionDisable($2)); }

	|	TOK_PATTERN_TYPE pattern
			{ current_rule->AddPattern($2, $1); }

	|	TOK_PATTERN_TYPE '[' rangeopt ']' pattern
			{
			if ( $3.offset > 0 )
				reporter->Warning("Offsets are currently ignored for patterns");
			current_rule->AddPattern($5, $1, 0, $3.len);
			}

	|	TOK_PAYLOAD_SIZE TOK_COMP integer
			{
			current_rule->AddCondition(
				new RuleConditionPayloadSize($3, (RuleConditionPayloadSize::Comp) ($2)));
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
			{ current_rule->AddCondition(new RuleConditionSameIP()); }

	|	TOK_SRC_IP TOK_COMP prefix_value_list
			{
			current_rule->AddHdrTest(new RuleHdrTest(
				RuleHdrTest::IPSrc,
				(RuleHdrTest::Comp) $2, *($3)));
			}

	|	TOK_SRC_PORT TOK_COMP value_list
			{ // Works for both TCP and UDP
			current_rule->AddHdrTest(new RuleHdrTest(
				RuleHdrTest::TCP, 0, 2,
				(RuleHdrTest::Comp) $2, $3));
			}

	|	TOK_TCP_STATE tcpstate_list
			{
			current_rule->AddCondition(new RuleConditionTCPState($2));
			}

	|	TOK_ACTIVE TOK_BOOL
			{ current_rule->SetActiveStatus($2); }
	;

hdr_expr:
		TOK_PROT '[' range ']' '&' integer TOK_COMP value
			{
			maskedvalue_list* vallist = new maskedvalue_list;
			MaskedValue* val = new MaskedValue();

			val->val = $8.val;
			val->mask = $6;
			vallist->append(val);

			$$ = new RuleHdrTest($1, $3.offset, $3.len,
					(RuleHdrTest::Comp) $7, vallist);
			}

	|	TOK_PROT '[' range ']' TOK_COMP value_list
			{
			$$ = new RuleHdrTest($1, $3.offset, $3.len,
						(RuleHdrTest::Comp) $5, $6);
			}
	;

value_list:
		value_list ',' value
			{ $1->append(new MaskedValue($3)); $$ = $1; }
	|	value_list ',' TOK_IDENT
			{ id_to_maskedvallist($3, $1); $$ = $1; }
	|	value
			{
			$$ = new maskedvalue_list();
			$$->append(new MaskedValue($1));
			}
	|	TOK_IDENT
			{
			$$ = new maskedvalue_list();
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
			$$ = new vector<IPPrefix>();
			$$->push_back(*($1));
			}
	|	TOK_IDENT
			{
			$$ = new vector<IPPrefix>();
			id_to_maskedvallist($1, 0, $$);
			}
	;

prefix_value:
		TOK_IP
			{
			$$ = new IPPrefix(IPAddr(IPv4, &($1.val), IPAddr::Host),
			                  ip4_mask_to_len($1.mask));
			}
	|	TOK_IP6
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

tcpstate_list:
		tcpstate_list ',' TOK_TCP_STATE_SYM
			{ $$ = $1 | $3; }
	|	TOK_TCP_STATE_SYM
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
	reporter->Error("Error in signature (%s:%d): %s\n",
			current_rule_file, rules_line_number+1, msg);
	rule_matcher->SetParseError();
	}

void rules_error(const char* msg, const char* addl)
	{
	reporter->Error("Error in signature (%s:%d): %s (%s)\n",
			current_rule_file, rules_line_number+1, msg, addl);
	rule_matcher->SetParseError();
	}

void rules_error(Rule* r, const char* msg)
	{
	const Location& l = r->GetLocation();
	reporter->Error("Error in signature %s (%s:%d): %s\n",
			r->ID(), l.filename, l.first_line, msg);
	rule_matcher->SetParseError();
	}

int rules_wrap(void)
	{
	return 1;
	}
