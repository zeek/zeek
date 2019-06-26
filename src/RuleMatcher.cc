#include <algorithm>
#include <functional>

#include "zeek-config.h"

#include "analyzer/Analyzer.h"
#include "RuleMatcher.h"
#include "DFA.h"
#include "NetVar.h"
#include "Scope.h"
#include "File.h"
#include "Reporter.h"

// FIXME: Things that are not fully implemented/working yet:
//
//		  - "ip-options" always evaluates to false
//		  - offsets for payload patterns are ignored
//			(but simulated by snort2bro by leading dots)
//		  - if a rule contains "PayloadSize" and application
//			specific patterns (like HTTP), but no "payload" patterns,
//			it may fail to match. Work-around: Insert an always
//			matching "payload" pattern (not done in snort2bro yet)
//		  - tcp-state always evaluates to true
//			(implemented but deactivated for comparison to Snort)

uint32 RuleHdrTest::idcounter = 0;

RuleHdrTest::RuleHdrTest(Prot arg_prot, uint32 arg_offset, uint32 arg_size,
				Comp arg_comp, maskedvalue_list* arg_vals)
	{
	prot = arg_prot;
	offset = arg_offset;
	size = arg_size;
	comp = arg_comp;
	vals = arg_vals;
	sibling = 0;
	child = 0;
	pattern_rules = 0;
	pure_rules = 0;
	ruleset = new IntSet;
	id = ++idcounter;
	level = 0;
	}

RuleHdrTest::RuleHdrTest(Prot arg_prot, Comp arg_comp, vector<IPPrefix> arg_v)
	{
	prot = arg_prot;
	offset = 0;
	size = 0;
	comp = arg_comp;
	vals = new maskedvalue_list;
	prefix_vals = arg_v;
	sibling = 0;
	child = 0;
	pattern_rules = 0;
	pure_rules = 0;
	ruleset = new IntSet;
	id = ++idcounter;
	level = 0;
	}

Val* RuleMatcher::BuildRuleStateValue(const Rule* rule,
					const RuleEndpointState* state) const
	{
	RecordVal* val = new RecordVal(signature_state);
	val->Assign(0, new StringVal(rule->ID()));
	val->Assign(1, state->GetAnalyzer()->BuildConnVal());
	val->Assign(2, val_mgr->GetBool(state->is_orig));
	val->Assign(3, val_mgr->GetCount(state->payload_size));
	return val;
	}

RuleHdrTest::RuleHdrTest(RuleHdrTest& h)
	{
	prot = h.prot;
	offset = h.offset;
	size = h.size;
	comp = h.comp;

	vals = new maskedvalue_list;
	loop_over_list(*h.vals, i)
		vals->append(new MaskedValue(*(*h.vals)[i]));

	prefix_vals = h.prefix_vals;

	for ( int j = 0; j < Rule::TYPES; ++j )
		{
		loop_over_list(h.psets[j], k)
			{
			PatternSet* orig_set = h.psets[j][k];
			PatternSet* copied_set = new PatternSet;
			copied_set->re = 0;
			copied_set->ids = orig_set->ids;
			loop_over_list(orig_set->patterns, l)
				copied_set->patterns.append(copy_string(orig_set->patterns[l]));
			delete copied_set;
			// TODO: Why do we create copied_set only to then
			// never use it?
			}
		}

	sibling = 0;
	child = 0;
	pattern_rules = 0;
	pure_rules = 0;
	ruleset = new IntSet;
	id = ++idcounter;
	level = 0;
	}

RuleHdrTest::~RuleHdrTest()
	{
	loop_over_list(*vals, i)
		delete (*vals)[i];
	delete vals;

	for ( int i = 0; i < Rule::TYPES; ++i )
		{
		loop_over_list(psets[i], j)
			delete psets[i][j]->re;
		}

	delete ruleset;
	}

bool RuleHdrTest::operator==(const RuleHdrTest& h)
	{
	if ( prot != h.prot || offset != h.offset || size != h.size ||
	     comp != h.comp || vals->length() != h.vals->length() )
		return false;

	loop_over_list(*vals, i)
		if ( (*vals)[i]->val != (*h.vals)[i]->val ||
		     (*vals)[i]->mask != (*h.vals)[i]->mask )
			return false;

	for ( size_t i = 0; i < prefix_vals.size(); ++i )
		if ( ! (prefix_vals[i] == h.prefix_vals[i]) )
			return false;

	return true;
	}

void RuleHdrTest::PrintDebug()
	{
	static const char* str_comp[] = { "<=", ">=", "<", ">", "==", "!=" };
	static const char* str_prot[] = { "", "ip", "ipv6", "icmp", "icmpv6", "tcp", "udp", "next", "ipsrc", "ipdst" };

	fprintf(stderr, "	RuleHdrTest %s[%d:%d] %s",
			str_prot[prot], offset, size, str_comp[comp]);

	loop_over_list(*vals, i)
		fprintf(stderr, " 0x%08x/0x%08x",
				(*vals)[i]->val, (*vals)[i]->mask);

	for ( size_t i = 0; i < prefix_vals.size(); ++i )
		fprintf(stderr, " %s", prefix_vals[i].AsString().c_str());

	fprintf(stderr, "\n");
	}

RuleEndpointState::RuleEndpointState(analyzer::Analyzer* arg_analyzer, bool arg_is_orig,
					  RuleEndpointState* arg_opposite,
					  analyzer::pia::PIA* arg_PIA)
	{
	payload_size = -1;
	analyzer = arg_analyzer;
	is_orig = arg_is_orig;

	opposite = arg_opposite;
	if ( opposite )
		opposite->opposite = this;

	pia = arg_PIA;
	}

RuleEndpointState::~RuleEndpointState()
	{
	loop_over_list(matchers, i)
		{
		delete matchers[i]->state;
		delete matchers[i];
		}

	loop_over_list(matched_text, j)
		delete matched_text[j];
	}

RuleFileMagicState::~RuleFileMagicState()
	{
	loop_over_list(matchers, i)
		{
		delete matchers[i]->state;
		delete matchers[i];
		}
	}

RuleMatcher::RuleMatcher(int arg_RE_level)
	{
	root = new RuleHdrTest(RuleHdrTest::NOPROT, 0, 0, RuleHdrTest::EQ,
				new maskedvalue_list);
	RE_level = arg_RE_level;
	}

RuleMatcher::~RuleMatcher()
	{
#ifdef MATCHER_PRINT_STATS
	DumpStats(stderr);
#endif
	Delete(root);

	loop_over_list(rules, i)
		delete rules[i];
	}

void RuleMatcher::Delete(RuleHdrTest* node)
	{
	RuleHdrTest* next;
	for ( RuleHdrTest* h = node->child; h; h = next )
		{
		next = h->sibling;
		Delete(h);
		}

	delete node;
	}

bool RuleMatcher::ReadFiles(const name_list& files)
	{
#ifdef USE_PERFTOOLS_DEBUG
	HeapLeakChecker::Disabler disabler;
#endif

	parse_error = false;

	for ( int i = 0; i < files.length(); ++i )
		{
		rules_in = open_file(find_file(files[i], bro_path(), ".sig"));

		if ( ! rules_in )
			{
			reporter->Error("Can't open signature file %s", files[i]);
			return false;
			}

		rules_line_number = 0;
		current_rule_file = files[i];
		rules_parse();
		fclose(rules_in);
		}

	if ( parse_error )
		return false;

	BuildRulesTree();

	string_list exprs[Rule::TYPES];
	int_list ids[Rule::TYPES];
	BuildRegEx(root, exprs, ids);

	return ! parse_error;
	}

void RuleMatcher::AddRule(Rule* rule)
	{
	if ( rules_by_id.Lookup(rule->ID()) )
		{
		rules_error("rule defined twice");
		return;
		}

	rules.append(rule);
	rules_by_id.Insert(rule->ID(), rule);
	}

void RuleMatcher::BuildRulesTree()
	{
	loop_over_list(rules, r)
		{
		if ( ! rules[r]->Active() )
			continue;

		rules[r]->SortHdrTests();
		InsertRuleIntoTree(rules[r], 0, root, 0);
		}
	}

void RuleMatcher::InsertRuleIntoTree(Rule* r, int testnr,
					RuleHdrTest* dest, int level)
	{
	// Initiliaze the preconditions
	loop_over_list(r->preconds, i)
		{
		Rule::Precond* pc = r->preconds[i];

		Rule* pc_rule = rules_by_id.Lookup(pc->id);
		if ( ! pc_rule )
			{
			rules_error(r, "unknown rule referenced");
			return;
			}

		pc->rule = pc_rule;
		pc_rule->dependents.append(r);
		}

	// All tests in tree already?
	if ( testnr >= r->hdr_tests.length() )
		{ // then insert it into the right list of the test
		if ( r->patterns.length() )
			{
			r->next = dest->pattern_rules;
			dest->pattern_rules = r;
			}
		else
			{
			r->next = dest->pure_rules;
			dest->pure_rules = r;
			}

		dest->ruleset->Insert(r->Index());
		return;
		}

	// Look for matching child.
	for ( RuleHdrTest* h = dest->child; h; h = h->sibling )
		if ( *h == *r->hdr_tests[testnr] )
			{
			InsertRuleIntoTree(r, testnr + 1, h, level + 1);
			return;
			}

	// Insert new child.
	RuleHdrTest* newtest = new RuleHdrTest(*r->hdr_tests[testnr]);
	newtest->sibling = dest->child;
	newtest->level = level + 1;
	dest->child = newtest;

	InsertRuleIntoTree(r, testnr + 1, newtest, level + 1);
	}

void RuleMatcher::BuildRegEx(RuleHdrTest* hdr_test, string_list* exprs,
				int_list* ids)
	{
	// For each type, get all patterns on this node.
	for ( Rule* r = hdr_test->pattern_rules; r; r = r->next )
		{
		loop_over_list(r->patterns, j)
			{
			Rule::Pattern* p = r->patterns[j];
			exprs[p->type].append(p->pattern);
			ids[p->type].append(p->id);
			}
		}

	// If we're above the RE_level, these patterns will form the regexprs.
	if ( hdr_test->level < RE_level )
		{
		for ( int i = 0; i < Rule::TYPES; ++i )
			if ( exprs[i].length() )
				BuildPatternSets(&hdr_test->psets[i], exprs[i], ids[i]);
		}

	// Get the patterns on all of our children.
	for ( RuleHdrTest* h = hdr_test->child; h; h = h->sibling )
		{
		string_list child_exprs[Rule::TYPES];
		int_list child_ids[Rule::TYPES];

		BuildRegEx(h, child_exprs, child_ids);

		for ( int i = 0; i < Rule::TYPES; ++i )
			{
			loop_over_list(child_exprs[i], j)
				{
				exprs[i].append(child_exprs[i][j]);
				ids[i].append(child_ids[i][j]);
				}
			}
		}

	// If we're on the RE_level, all patterns gathered now
	// form the regexprs.
	if ( hdr_test->level == RE_level )
		{
		for ( int i = 0; i < Rule::TYPES; ++i )
			if ( exprs[i].length() )
				BuildPatternSets(&hdr_test->psets[i], exprs[i], ids[i]);
		}

	// If we're below the RE_level, the regexprs remains empty.
	}

void RuleMatcher::BuildPatternSets(RuleHdrTest::pattern_set_list* dst,
				const string_list& exprs, const int_list& ids)
	{
	assert(exprs.length() == ids.length());

	// We build groups of at most sig_max_group_size regexps.

	string_list group_exprs;
	int_list group_ids;

	for ( int i = 0; i < exprs.length() + 1 /* sic! */; i++ )
		{
		if ( i < exprs.length() )
			{
			group_exprs.append(exprs[i]);
			group_ids.append(ids[i]);
			}

		if ( group_exprs.length() > sig_max_group_size ||
		     i == exprs.length() )
			{
			RuleHdrTest::PatternSet* set =
				new RuleHdrTest::PatternSet;
			set->re = new Specific_RE_Matcher(MATCH_EXACTLY, 1);
			set->re->CompileSet(group_exprs, group_ids);
			set->patterns = group_exprs;
			set->ids = group_ids;
			dst->append(set);

			group_exprs.clear();
			group_ids.clear();
			}
		}
	}

// Get a 8/16/32-bit value from the given position in the packet header
static inline uint32 getval(const u_char* data, int size)
	{
	switch ( size ) {
	case 1:
		return *(uint8*) data;

	case 2:
		return ntohs(*(uint16*) data);

	case 4:
		return ntohl(*(uint32*) data);

	default:
		reporter->InternalError("illegal HdrTest size");
	}

	// Should not be reached.
	return 0;
	}


// Evaluate a value list (matches if at least one value matches).
template <typename FuncT>
static inline bool match_or(const maskedvalue_list& mvals, uint32 v, FuncT comp)
	{
	loop_over_list(mvals, i)
		{
		if ( comp(v & mvals[i]->mask, mvals[i]->val) )
			return true;
		}
	return false;
	}

// Evaluate a prefix list (matches if at least one value matches).
template <typename FuncT>
static inline bool match_or(const vector<IPPrefix>& prefixes, const IPAddr& a,
                            FuncT comp)
	{
	for ( size_t i = 0; i < prefixes.size(); ++i )
		{
		IPAddr masked(a);
		masked.Mask(prefixes[i].LengthIPv6());
		if ( comp(masked, prefixes[i].Prefix()) )
			return true;
		}
	return false;
	}

// Evaluate a value list (doesn't match if any value matches).
template <typename FuncT>
static inline bool match_not_and(const maskedvalue_list& mvals, uint32 v,
                                 FuncT comp)
	{
	loop_over_list(mvals, i)
		{
		if ( comp(v & mvals[i]->mask, mvals[i]->val) )
			return false;
		}
	return true;
	}

// Evaluate a prefix list (doesn't match if any value matches).
template <typename FuncT>
static inline bool match_not_and(const vector<IPPrefix>& prefixes,
                                 const IPAddr& a, FuncT comp)
	{
	for ( size_t i = 0; i < prefixes.size(); ++i )
		{
		IPAddr masked(a);
		masked.Mask(prefixes[i].LengthIPv6());
		if ( comp(masked, prefixes[i].Prefix()) )
			return false;
		}
	return true;
	}

static inline bool compare(const maskedvalue_list& mvals, uint32 v,
                           RuleHdrTest::Comp comp)
	{
	switch ( comp ) {
		case RuleHdrTest::EQ:
			return match_or(mvals, v, std::equal_to<uint32>());
			break;

		case RuleHdrTest::NE:
			return match_not_and(mvals, v, std::equal_to<uint32>());
			break;

		case RuleHdrTest::LT:
			return match_or(mvals, v, std::less<uint32>());
			break;

		case RuleHdrTest::GT:
			return match_or(mvals, v, std::greater<uint32>());
			break;

		case RuleHdrTest::LE:
			return match_or(mvals, v, std::less_equal<uint32>());
			break;

		case RuleHdrTest::GE:
			return match_or(mvals, v, std::greater_equal<uint32>());
			break;

		default:
			reporter->InternalError("unknown RuleHdrTest comparison type");
			break;
	}
	return false;
	}

static inline bool compare(const vector<IPPrefix>& prefixes, const IPAddr& a,
                           RuleHdrTest::Comp comp)
	{
	switch ( comp ) {
		case RuleHdrTest::EQ:
			return match_or(prefixes, a, std::equal_to<IPAddr>());
			break;

		case RuleHdrTest::NE:
			return match_not_and(prefixes, a, std::equal_to<IPAddr>());
			break;

		case RuleHdrTest::LT:
			return match_or(prefixes, a, std::less<IPAddr>());
			break;

		case RuleHdrTest::GT:
			return match_or(prefixes, a, std::greater<IPAddr>());
			break;

		case RuleHdrTest::LE:
			return match_or(prefixes, a, std::less_equal<IPAddr>());
			break;

		case RuleHdrTest::GE:
			return match_or(prefixes, a, std::greater_equal<IPAddr>());
			break;

		default:
			reporter->InternalError("unknown RuleHdrTest comparison type");
			break;
	}
	return false;
	}

RuleFileMagicState* RuleMatcher::InitFileMagic() const
	{
	RuleFileMagicState* state = new RuleFileMagicState();

	loop_over_list(root->psets[Rule::FILE_MAGIC], i)
		{
		RuleHdrTest::PatternSet* set = root->psets[Rule::FILE_MAGIC][i];
		assert(set->re);
		RuleFileMagicState::Matcher* m = new RuleFileMagicState::Matcher;
		m->state = new RE_Match_State(set->re);
		state->matchers.append(m);
		}

	// Save some memory.
	state->matchers.resize(0);
	return state;
	}

bool RuleMatcher::AllRulePatternsMatched(const Rule* r, MatchPos matchpos,
                                         const AcceptingMatchSet& ams)
	{
	DBG_LOG(DBG_RULES, "Checking rule: %s", r->id);

	// Check whether all patterns of the rule have matched.
	loop_over_list(r->patterns, j)
		{
		if ( ams.find(r->patterns[j]->id) == ams.end() )
			return false;

		// See if depth is satisfied.
		if ( matchpos > r->patterns[j]->offset + r->patterns[j]->depth )
			return false;

		// FIXME: How to check for offset ??? ###
		}

	DBG_LOG(DBG_RULES, "All patterns of rule satisfied");

	return true;
	}

RuleMatcher::MIME_Matches* RuleMatcher::Match(RuleFileMagicState* state,
                                              const u_char* data, uint64 len,
                                              MIME_Matches* rval) const
	{
	if ( ! rval )
		rval = new MIME_Matches();

	if ( ! state )
		{
		reporter->Warning("RuleFileMagicState not initialized yet.");
		return rval;
		}

#ifdef DEBUG
	if ( debug_logger.IsEnabled(DBG_RULES) )
		{
		const char* s = fmt_bytes(reinterpret_cast<const char*>(data),
		                          min(40, static_cast<int>(len)));
		DBG_LOG(DBG_RULES, "Matching %s rules on |%s%s|",
		        Rule::TypeToString(Rule::FILE_MAGIC), s,
		        len > 40 ? "..." : "");
		}
#endif

	bool newmatch = false;

	loop_over_list(state->matchers, x)
		{
		RuleFileMagicState::Matcher* m = state->matchers[x];

		if ( m->state->Match(data, len, true, false, true) )
			newmatch = true;
		}

	if ( ! newmatch )
		return rval;

	DBG_LOG(DBG_RULES, "New pattern match found");

	AcceptingMatchSet accepted_matches;

	loop_over_list(state->matchers, y)
		{
		RuleFileMagicState::Matcher* m = state->matchers[y];
		const AcceptingMatchSet& ams = m->state->AcceptedMatches();
		accepted_matches.insert(ams.begin(), ams.end());
		}

	// Find rules for which patterns have matched.
	set<Rule*> rule_matches;

	for ( AcceptingMatchSet::const_iterator it = accepted_matches.begin();
	      it != accepted_matches.end(); ++it )
		{
		AcceptIdx aidx = it->first;
		MatchPos mpos = it->second;

		Rule* r = Rule::rule_table[aidx - 1];

		if ( AllRulePatternsMatched(r, mpos, accepted_matches) )
			rule_matches.insert(r);
		}

	for ( set<Rule*>::const_iterator it = rule_matches.begin();
	      it != rule_matches.end(); ++it )
		{
		Rule* r = *it;

		loop_over_list(r->actions, rai)
			{
			const RuleActionMIME* ram =
			       dynamic_cast<const RuleActionMIME*>(r->actions[rai]);

			if ( ! ram )
				continue;

			set<string>& ss = (*rval)[ram->GetStrength()];
			ss.insert(ram->GetMIME());
			}
		}

	return rval;
	}

RuleEndpointState* RuleMatcher::InitEndpoint(analyzer::Analyzer* analyzer,
						const IP_Hdr* ip, int caplen,
						RuleEndpointState* opposite,
						bool from_orig, analyzer::pia::PIA* pia)
	{
	RuleEndpointState* state =
		new RuleEndpointState(analyzer, from_orig, opposite, pia);

	rule_hdr_test_list tests;
	tests.append(root);

	loop_over_list(tests, h)
		{
		RuleHdrTest* hdr_test = tests[h];

		DBG_LOG(DBG_RULES, "HdrTest %d matches (%s%s)", hdr_test->id,
				hdr_test->pattern_rules ? "+" : "-",
				hdr_test->pure_rules ? "+" : "-");

		// Current HdrTest node matches the packet, so remember it
		// if we have any rules on it.
		if ( hdr_test->pattern_rules || hdr_test->pure_rules )
			state->hdr_tests.append(hdr_test);

		// Evaluate all rules on this node which don't contain
		// any patterns.
		for ( Rule* r = hdr_test->pure_rules; r; r = r->next )
			if ( EvalRuleConditions(r, state, 0, 0, 0) )
				ExecRuleActions(r, state, 0, 0, 0);

		// If we're on or above the RE_level, we may have some
		// pattern matching to do.
		if ( hdr_test->level <= RE_level )
			{
			for ( int i = 0; i < Rule::TYPES; ++i )
				{
				loop_over_list(hdr_test->psets[i], j)
					{
					RuleHdrTest::PatternSet* set =
						hdr_test->psets[i][j];

					assert(set->re);

					RuleEndpointState::Matcher* m =
						new RuleEndpointState::Matcher;
					m->state = new RE_Match_State(set->re);
					m->type = (Rule::PatternType) i;
					state->matchers.append(m);
					}
				}
			}

		if ( ip )
			{
			// Descend the RuleHdrTest tree further.
			for ( RuleHdrTest* h = hdr_test->child; h;
			      h = h->sibling )
				{
				bool match = false;

				// Evaluate the header test.
				switch ( h->prot ) {
				case RuleHdrTest::NEXT:
					match = compare(*h->vals, ip->NextProto(), h->comp);
					break;

				case RuleHdrTest::IP:
					if ( ! ip->IP4_Hdr() )
						continue;

					match = compare(*h->vals, getval((const u_char*)ip->IP4_Hdr() + h->offset, h->size), h->comp);
					break;

				case RuleHdrTest::IPv6:
					if ( ! ip->IP6_Hdr() )
						continue;

					match = compare(*h->vals, getval((const u_char*)ip->IP6_Hdr() + h->offset, h->size), h->comp);
					break;

				case RuleHdrTest::ICMP:
				case RuleHdrTest::ICMPv6:
				case RuleHdrTest::TCP:
				case RuleHdrTest::UDP:
					match = compare(*h->vals, getval(ip->Payload() + h->offset, h->size), h->comp);
					break;

				case RuleHdrTest::IPSrc:
					match = compare(h->prefix_vals, ip->IPHeaderSrcAddr(), h->comp);
					break;

				case RuleHdrTest::IPDst:
					match = compare(h->prefix_vals, ip->IPHeaderDstAddr(), h->comp);
					break;

				default:
					reporter->InternalError("unknown RuleHdrTest protocol type");
					break;
				}

				if ( match )
					tests.append(h);
				}
			}
		}
	// Save some memory.
	state->hdr_tests.resize(0);
	state->matchers.resize(0);

	// Send BOL to payload matchers.
	Match(state, Rule::PAYLOAD, (const u_char *) "", 0, true, false, false);

	return state;
	}

void RuleMatcher::Match(RuleEndpointState* state, Rule::PatternType type,
			const u_char* data, int data_len,
			bool bol, bool eol, bool clear)
	{
	if ( ! state )
		{
		reporter->Warning("RuleEndpointState not initialized yet.");
		return;
		}

	// FIXME: There is probably some room for performance improvements
	// in this method.  For example, it *may* help to use an IntSet
	// for 'accepted' (that depends on the average number of matching
	// patterns).

	bool newmatch = false;

#ifdef DEBUG
	if ( debug_logger.IsEnabled(DBG_RULES) )
		{
		const char* s =
			fmt_bytes((const char *) data, min(40, data_len));

		DBG_LOG(DBG_RULES, "Matching %s rules [%d,%d] on |%s%s|",
				Rule::TypeToString(type), bol, eol, s,
				data_len > 40 ? "..." : "");
		}
#endif

	// Remember size of first non-null data.
	if ( type == Rule::PAYLOAD )
		{
		bol = state->payload_size < 0;

		if ( state->payload_size <= 0 && data_len )
			state->payload_size = data_len;

		else if ( state->payload_size < 0 )
			state->payload_size = 0;
		}

	// Feed data into all relevant matchers.
	loop_over_list(state->matchers, x)
		{
		RuleEndpointState::Matcher* m = state->matchers[x];
		if ( m->type == type &&
		     m->state->Match((const u_char*) data, data_len,
					bol, eol, clear) )
			newmatch = true;
		}

	// If no new match found, we're already done.
	if ( ! newmatch )
		return;

	DBG_LOG(DBG_RULES, "New pattern match found");

	AcceptingMatchSet accepted_matches;

	loop_over_list(state->matchers, y )
		{
		RuleEndpointState::Matcher* m = state->matchers[y];
		const AcceptingMatchSet& ams = m->state->AcceptedMatches();
		accepted_matches.insert(ams.begin(), ams.end());
		}

	// Determine the rules for which all patterns have matched.
	// This code should be fast enough as long as there are only very few
	// matched patterns per connection (which is a plausible assumption).

	// Find rules for which patterns have matched.
	set<Rule*> rule_matches;

	for ( AcceptingMatchSet::const_iterator it = accepted_matches.begin();
	      it != accepted_matches.end(); ++it )
		{
		AcceptIdx aidx = it->first;
		MatchPos mpos = it->second;

		Rule* r = Rule::rule_table[aidx - 1];

		if ( AllRulePatternsMatched(r, mpos, accepted_matches) )
			rule_matches.insert(r);
		}

	// Check which of the matching rules really belong to any of our nodes.

	for ( set<Rule*>::const_iterator it = rule_matches.begin();
	      it != rule_matches.end(); ++it )
		{
		Rule* r = *it;

		DBG_LOG(DBG_RULES, "Accepted rule: %s", r->id);

		loop_over_list(state->hdr_tests, k)
			{
			RuleHdrTest* h = state->hdr_tests[k];

			DBG_LOG(DBG_RULES, "Checking for accepted rule on HdrTest %d", h->id);

			// Skip if rule does not belong to this node.
			if ( ! h->ruleset->Contains(r->Index()) )
				continue;

			DBG_LOG(DBG_RULES, "On current node");

			// Skip if rule already fired for this connection.
			if ( state->matched_rules.is_member(r->Index()) )
				continue;

			// Remember that all patterns have matched.
			if ( ! state->matched_by_patterns.is_member(r) )
				{
				state->matched_by_patterns.append(r);
				BroString* s = new BroString(data, data_len, 0);
				state->matched_text.append(s);
				}

			DBG_LOG(DBG_RULES, "And has not already fired");
			// Eval additional conditions.
			if ( ! EvalRuleConditions(r, state, data, data_len, 0) )
				continue;

			// Found a match.
			ExecRuleActions(r, state, data, data_len, 0);
			}
		}
	}

void RuleMatcher::FinishEndpoint(RuleEndpointState* state)
	{
	// Send EOL to payload matchers.
	Match(state, Rule::PAYLOAD, (const u_char *) "", 0, false, true, false);

	// Some of the pure rules may match at the end of the connection,
	// although they have not matched at the beginning. So, we have
	// to test the candidates here.

	ExecPureRules(state, 1);

	loop_over_list(state->matched_by_patterns, i)
		ExecRulePurely(state->matched_by_patterns[i],
				state->matched_text[i], state, 1);
	}

void RuleMatcher::ExecPureRules(RuleEndpointState* state, bool eos)
	{
	loop_over_list(state->hdr_tests, i)
		{
		RuleHdrTest* hdr_test = state->hdr_tests[i];
		for ( Rule* r = hdr_test->pure_rules; r; r = r->next )
			ExecRulePurely(r, 0, state, eos);
		}
	}

bool RuleMatcher::ExecRulePurely(Rule* r, BroString* s,
				 RuleEndpointState* state, bool eos)
	{
	if ( state->matched_rules.is_member(r->Index()) )
		return false;

	DBG_LOG(DBG_RULES, "Checking rule %s purely", r->ID());

	if ( EvalRuleConditions(r, state, 0, 0, eos) )
		{
		DBG_LOG(DBG_RULES, "MATCH!");

		if ( s )
			ExecRuleActions(r, state, s->Bytes(), s->Len(), eos);
		else
			ExecRuleActions(r, state, 0, 0, eos);

		return true;
		}

	return false;
	}

bool RuleMatcher::EvalRuleConditions(Rule* r, RuleEndpointState* state,
		const u_char* data, int len, bool eos)
	{
	DBG_LOG(DBG_RULES, "Evaluating conditions for rule %s", r->ID());

	// Check for other rules which have to match first.
	loop_over_list(r->preconds, i)
		{
		Rule::Precond* pc = r->preconds[i];

		RuleEndpointState* pc_state = state;

		if ( pc->opposite_dir )
			{
			if ( ! state->opposite )
				// No rule matching for other direction yet.
				return false;

			pc_state = state->opposite;
			}

		if ( ! pc->negate )
			{
			if ( ! pc_state->matched_rules.is_member(pc->rule->Index()) )
				// Precond rule has not matched yet.
				return false;
			}
		else
			{
			// Only at eos can we decide about negated conditions.
			if ( ! eos )
				return false;

			if ( pc_state->matched_rules.is_member(pc->rule->Index()) )
				return false;
			}
		}

	loop_over_list(r->conditions, l)
		if ( ! r->conditions[l]->DoMatch(r, state, data, len) )
			return false;

	DBG_LOG(DBG_RULES, "Conditions met: MATCH! %s", r->ID());
	return true;
	}

void RuleMatcher::ExecRuleActions(Rule* r, RuleEndpointState* state,
				const u_char* data, int len, bool eos)
	{
	if ( state->opposite &&
	     state->opposite->matched_rules.is_member(r->Index()) )
		// We have already executed the actions.
		return;

	state->matched_rules.append(r->Index());

	loop_over_list(r->actions, i)
		r->actions[i]->DoAction(r, state, data, len);

	// This rule may trigger some other rules; check them.
	loop_over_list(r->dependents, j)
		{
		Rule* dep = (r->dependents)[j];
		ExecRule(dep, state, eos);
		if ( state->opposite )
			ExecRule(dep, state->opposite, eos);
		}
	}

void RuleMatcher::ExecRule(Rule* rule, RuleEndpointState* state, bool eos)
	{
	// Nothing to do if it has already matched.
	if ( state->matched_rules.is_member(rule->Index()) )
		return;

	loop_over_list(state->hdr_tests, i)
		{
		RuleHdrTest* h = state->hdr_tests[i];

		// Is it on this HdrTest at all?
		if ( ! h->ruleset->Contains(rule->Index()) )
			continue;

		// Is it a pure rule?
		for ( Rule* r = h->pure_rules; r; r = r->next )
			if ( r == rule )
				{ // found, so let's evaluate it
				ExecRulePurely(rule, 0, state, eos);
				return;
				}

		// It must be a non-pure rule. It can only match right now if
		// all its patterns are satisfied already.
		int pos = state->matched_by_patterns.member_pos(rule);
		if ( pos >= 0 )
			{ // they are, so let's evaluate it
			ExecRulePurely(rule, state->matched_text[pos], state, eos);
			return;
			}
		}
	}

void RuleMatcher::ClearEndpointState(RuleEndpointState* state)
	{
	ExecPureRules(state, 1);

	state->payload_size = -1;

	loop_over_list(state->matchers, j)
		state->matchers[j]->state->Clear();
	}

void RuleMatcher::ClearFileMagicState(RuleFileMagicState* state) const
	{
	loop_over_list(state->matchers, j)
		state->matchers[j]->state->Clear();
	}

void RuleMatcher::PrintDebug()
	{
	loop_over_list(rules, i)
		rules[i]->PrintDebug();

	fprintf(stderr, "\n---------------\n");

	PrintTreeDebug(root);
	}

static inline void indent(int level)
	{
	for ( int i = level * 2; i; --i )
		fputc(' ', stderr);
	}

void RuleMatcher::PrintTreeDebug(RuleHdrTest* node)
	{
	for ( int i = 0; i < Rule::TYPES; ++i )
		{
		indent(node->level);
		loop_over_list(node->psets[i], j)
			{
			RuleHdrTest::PatternSet* set = node->psets[i][j];

			fprintf(stderr,
				"[%d patterns in %s group %d from %d rules]\n",
				set->patterns.length(),
				Rule::TypeToString((Rule::PatternType) i), j,
				set->ids.length());
			}
		}

	for ( Rule* r = node->pattern_rules; r; r = r->next )
		{
		indent(node->level);
		fprintf(stderr, "Pattern rule %s (%d/%d)\n", r->id, r->idx,
				node->ruleset->Contains(r->Index()));
		}

	for ( Rule* r = node->pure_rules; r; r = r->next )
		{
		indent(node->level);
		fprintf(stderr, "Pure rule %s (%d/%d)\n", r->id, r->idx,
				node->ruleset->Contains(r->Index()));
		}

	for ( RuleHdrTest* h = node->child; h; h = h->sibling )
		{
		indent(node->level);
		fprintf(stderr, "Test %4d\n", h->id);
		PrintTreeDebug(h);
		}
	}

void RuleMatcher::GetStats(Stats* stats, RuleHdrTest* hdr_test)
	{
	if ( ! hdr_test )
		{
		stats->matchers = 0;
		stats->dfa_states = 0;
		stats->computed = 0;
		stats->mem = 0;
		stats->hits = 0;
		stats->misses = 0;
		stats->nfa_states = 0;
		hdr_test = root;
		}

	DFA_State_Cache::Stats cstats;

	for ( int i = 0; i < Rule::TYPES; ++i )
		{
		loop_over_list(hdr_test->psets[i], j)
			{
			RuleHdrTest::PatternSet* set = hdr_test->psets[i][j];
			assert(set->re);

			++stats->matchers;
			set->re->DFA()->Cache()->GetStats(&cstats);

			stats->dfa_states += cstats.dfa_states;
			stats->computed += cstats.computed;
			stats->mem += cstats.mem;
			stats->hits += cstats.hits;
			stats->misses += cstats.misses;
			stats->nfa_states += cstats.nfa_states;
			}
		}

	for ( RuleHdrTest* h = hdr_test->child; h; h = h->sibling )
		GetStats(stats, h);
	}

void RuleMatcher::DumpStats(BroFile* f)
	{
	Stats stats;
	GetStats(&stats);

	f->Write(fmt("%.6f computed dfa states = %d; classes = ??; "
			"computed trans. = %d; matchers = %d; mem = %d\n",
			network_time, stats.dfa_states, stats.computed,
			stats.matchers, stats.mem));
	f->Write(fmt("%.6f DFA cache hits = %d; misses = %d\n", network_time,
			stats.hits, stats.misses));

	DumpStateStats(f, root);
	}

void RuleMatcher::DumpStateStats(BroFile* f, RuleHdrTest* hdr_test)
	{
	if ( ! hdr_test )
		return;

	for ( int i = 0; i < Rule::TYPES; i++ )
		{
		loop_over_list(hdr_test->psets[i], j)
			{
			RuleHdrTest::PatternSet* set = hdr_test->psets[i][j];
			assert(set->re);

			f->Write(fmt("%.6f %d DFA states in %s group %d from sigs ", network_time,
					 set->re->DFA()->NumStates(),
					 Rule::TypeToString((Rule::PatternType)i), j));

			loop_over_list(set->ids, k)
				{
				Rule* r = Rule::rule_table[set->ids[k] - 1];
				f->Write(fmt("%s ", r->ID()));
				}

			f->Write("\n");
			}
		}

	for ( RuleHdrTest* h = hdr_test->child; h; h = h->sibling )
		DumpStateStats(f, h);
	}

static Val* get_bro_val(const char* label)
	{
	ID* id = lookup_ID(label, GLOBAL_MODULE_NAME, false);
	if ( ! id )
		{
		rules_error("unknown script-level identifier", label);
		return 0;
		}

	Val* rval = id->ID_Val();
	Unref(id);

	return rval;
	}


// Converts an atomic Val and appends it to the list.  For subnet types,
// if the prefix_vector param isn't null, appending to that is preferred
// over appending to the masked val list.
static bool val_to_maskedval(Val* v, maskedvalue_list* append_to,
                             vector<IPPrefix>* prefix_vector)
	{
	MaskedValue* mval = new MaskedValue;

	switch ( v->Type()->Tag() ) {
		case TYPE_PORT:
			mval->val = v->AsPortVal()->Port();
			mval->mask = 0xffffffff;
			break;

		case TYPE_BOOL:
		case TYPE_COUNT:
		case TYPE_ENUM:
		case TYPE_INT:
			mval->val = v->CoerceToUnsigned();
			mval->mask = 0xffffffff;
			break;

		case TYPE_SUBNET:
			{
			if ( prefix_vector )
				{
				prefix_vector->push_back(v->AsSubNet());
				delete mval;
				return true;
				}
			else
				{
				const uint32* n;
				uint32 m[4];
				v->AsSubNet().Prefix().GetBytes(&n);
				v->AsSubNetVal()->Mask().CopyIPv6(m);

				for ( unsigned int i = 0; i < 4; ++i )
					m[i] = ntohl(m[i]);

				bool is_v4_mask = m[0] == 0xffffffff &&
				                          m[1] == m[0] && m[2] == m[0];


				if ( v->AsSubNet().Prefix().GetFamily() == IPv4 && is_v4_mask )
					{
					mval->val = ntohl(*n);
					mval->mask = m[3];
					}
				else
					{
					rules_error("IPv6 subnets not supported");
					mval->val = 0;
					mval->mask = 0;
					}
				}
			}
			break;

		default:
			rules_error("Wrong type of identifier");
			delete mval;
			return false;
	}

	append_to->append(mval);

	return true;
	}

void id_to_maskedvallist(const char* id, maskedvalue_list* append_to,
                         vector<IPPrefix>* prefix_vector)
	{
	Val* v = get_bro_val(id);
	if ( ! v )
		return;

	if ( v->Type()->Tag() == TYPE_TABLE )
		{
		ListVal* lv = v->AsTableVal()->ConvertToPureList();
		val_list* vals = lv->Vals();
		loop_over_list(*vals, i )
			if ( ! val_to_maskedval((*vals)[i], append_to, prefix_vector) )
				{
				Unref(lv);
				return;
				}

		Unref(lv);
		}

	else
		val_to_maskedval(v, append_to, prefix_vector);
	}

char* id_to_str(const char* id)
	{
	const BroString* src;
	char* dst;

	Val* v = get_bro_val(id);
	if ( ! v )
		goto error;

	if ( v->Type()->Tag() != TYPE_STRING )
		{
		rules_error("Identifier must refer to string");
		goto error;
		}

	src = v->AsString();
	dst = new char[src->Len()+1];
	memcpy(dst, src->Bytes(), src->Len());
	*(dst+src->Len()) = '\0';
	return dst;

error:
	char* dummy = copy_string("<error>");
	return dummy;
	}

uint32 id_to_uint(const char* id)
	{
	Val* v = get_bro_val(id);
	if ( ! v )
		return 0;

	TypeTag t = v->Type()->Tag();

	if ( t == TYPE_BOOL || t == TYPE_COUNT || t == TYPE_ENUM ||
	     t == TYPE_INT || t == TYPE_PORT )
		return v->CoerceToUnsigned();

	rules_error("Identifier must refer to integer");
	return 0;
	}

void RuleMatcherState::InitEndpointMatcher(analyzer::Analyzer* analyzer, const IP_Hdr* ip,
					   int caplen, bool from_orig, analyzer::pia::PIA* pia)
	{
	if ( ! rule_matcher )
		return;

	if ( from_orig )
		{
		if ( orig_match_state )
			{
			rule_matcher->FinishEndpoint(orig_match_state);
			delete orig_match_state;
			}

		orig_match_state =
			rule_matcher->InitEndpoint(analyzer, ip, caplen,
					resp_match_state, from_orig, pia);
		}

	else
		{
		if ( resp_match_state )
			{
			rule_matcher->FinishEndpoint( resp_match_state );
			delete resp_match_state;
			}

		resp_match_state =
			rule_matcher->InitEndpoint(analyzer, ip, caplen,
					orig_match_state, from_orig, pia);
		}
	}

void RuleMatcherState::FinishEndpointMatcher()
	{
	if ( ! rule_matcher )
		return;

	if ( orig_match_state )
		rule_matcher->FinishEndpoint(orig_match_state);

	if ( resp_match_state )
		rule_matcher->FinishEndpoint(resp_match_state);

	delete orig_match_state;
	delete resp_match_state;

	orig_match_state = resp_match_state = 0;
	}

void RuleMatcherState::Match(Rule::PatternType type, const u_char* data,
				int data_len, bool from_orig,
				bool bol, bool eol, bool clear)
	{
	if ( ! rule_matcher )
		return;

	rule_matcher->Match(from_orig ? orig_match_state : resp_match_state,
					type, data, data_len, bol, eol, clear);
	}

void RuleMatcherState::ClearMatchState(bool orig)
	{
	if ( ! rule_matcher )
		return;

	if ( orig )
		{
		if ( orig_match_state )
			rule_matcher->ClearEndpointState(orig_match_state);
		}

	else if ( resp_match_state )
		rule_matcher->ClearEndpointState(resp_match_state);
	}
