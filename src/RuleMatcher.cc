
#include "zeek/RuleMatcher.h"

#include "zeek/zeek-config.h"

#include <algorithm>
#include <functional>

#include "zeek/DFA.h"
#include "zeek/DebugLogger.h"
#include "zeek/File.h"
#include "zeek/ID.h"
#include "zeek/IP.h"
#include "zeek/IPAddr.h"
#include "zeek/IntSet.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RuleAction.h"
#include "zeek/RuleCondition.h"
#include "zeek/RunState.h"
#include "zeek/Scope.h"
#include "zeek/Var.h"
#include "zeek/ZeekString.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/module_util.h"

using namespace std;

// Functions exposed by rule-scan.l
extern void rules_set_input_from_buffer(const char* data, size_t size);
extern void rules_set_input_from_file(FILE* f);
extern void rules_parse_input();

namespace zeek::detail
	{

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

uint32_t RuleHdrTest::idcounter = 0;

static bool is_member_of(const int_list& l, int_list::value_type v)
	{
	return std::find(l.begin(), l.end(), v) != l.end();
	}

RuleHdrTest::RuleHdrTest(Prot arg_prot, uint32_t arg_offset, uint32_t arg_size, Comp arg_comp,
                         maskedvalue_list* arg_vals)
	{
	prot = arg_prot;
	offset = arg_offset;
	size = arg_size;
	comp = arg_comp;
	vals = arg_vals;
	sibling = nullptr;
	child = nullptr;
	pattern_rules = nullptr;
	pure_rules = nullptr;
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
	prefix_vals = std::move(arg_v);
	sibling = nullptr;
	child = nullptr;
	pattern_rules = nullptr;
	pure_rules = nullptr;
	ruleset = new IntSet;
	id = ++idcounter;
	level = 0;
	}

Val* RuleMatcher::BuildRuleStateValue(const Rule* rule, const RuleEndpointState* state) const
	{
	static auto signature_state = id::find_type<RecordType>("signature_state");
	auto* val = new RecordVal(signature_state);
	val->Assign(0, rule->ID());
	val->Assign(1, state->GetAnalyzer()->ConnVal());
	val->Assign(2, state->is_orig);
	val->Assign(3, state->payload_size);
	return val;
	}

RuleHdrTest::RuleHdrTest(RuleHdrTest& h)
	{
	prot = h.prot;
	offset = h.offset;
	size = h.size;
	comp = h.comp;

	vals = new maskedvalue_list;
	for ( const auto& val : *h.vals )
		vals->push_back(new MaskedValue(*val));

	prefix_vals = h.prefix_vals;

	for ( int j = 0; j < Rule::TYPES; ++j )
		{
		for ( PatternSet* orig_set : h.psets[j] )
			{
			PatternSet* copied_set = new PatternSet;
			copied_set->re = nullptr;
			copied_set->ids = orig_set->ids;
			for ( const auto& pattern : orig_set->patterns )
				copied_set->patterns.push_back(util::copy_string(pattern));
			delete copied_set;
			// TODO: Why do we create copied_set only to then
			// never use it?
			}
		}

	sibling = nullptr;
	child = nullptr;
	pattern_rules = nullptr;
	pure_rules = nullptr;
	ruleset = new IntSet;
	id = ++idcounter;
	level = 0;
	}

RuleHdrTest::~RuleHdrTest()
	{
	for ( auto val : *vals )
		delete val;
	delete vals;

	for ( int i = 0; i < Rule::TYPES; ++i )
		{
		for ( auto pset : psets[i] )
			{
			delete pset->re;
			delete pset;
			}
		}

	delete ruleset;
	}

bool RuleHdrTest::operator==(const RuleHdrTest& h)
	{
	if ( prot != h.prot || offset != h.offset || size != h.size || comp != h.comp ||
	     vals->length() != h.vals->length() )
		return false;

	loop_over_list(*vals, i) if ( (*vals)[i]->val != (*h.vals)[i]->val ||
	                              (*vals)[i]->mask != (*h.vals)[i]->mask ) return false;

	for ( size_t i = 0; i < prefix_vals.size(); ++i )
		if ( ! (prefix_vals[i] == h.prefix_vals[i]) )
			return false;

	return true;
	}

void RuleHdrTest::PrintDebug()
	{
	static const char* str_comp[] = {"<=", ">=", "<", ">", "==", "!="};
	static const char* str_prot[] = {"",    "ip",  "ipv6", "icmp",  "icmpv6",
	                                 "tcp", "udp", "next", "ipsrc", "ipdst"};

	fprintf(stderr, "	RuleHdrTest %s[%d:%d] %s", str_prot[prot], offset, size, str_comp[comp]);

	for ( const auto& val : *vals )
		fprintf(stderr, " 0x%08x/0x%08x", val->val, val->mask);

	for ( const auto& prefix : prefix_vals )
		fprintf(stderr, " %s", prefix.AsString().c_str());

	fprintf(stderr, "\n");
	}

RuleEndpointState::RuleEndpointState(analyzer::Analyzer* arg_analyzer, bool arg_is_orig,
                                     RuleEndpointState* arg_opposite, analyzer::pia::PIA* arg_PIA)
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
	for ( auto matcher : matchers )
		{
		delete matcher->state;
		delete matcher;
		}

	for ( auto text : matched_text )
		delete text;
	}

RuleFileMagicState::~RuleFileMagicState()
	{
	for ( auto matcher : matchers )
		{
		delete matcher->state;
		delete matcher;
		}
	}

RuleMatcher::RuleMatcher(int arg_RE_level)
	{
	root = new RuleHdrTest(RuleHdrTest::NOPROT, 0, 0, RuleHdrTest::EQ, new maskedvalue_list);
	RE_level = arg_RE_level;
	parse_error = false;
	has_non_file_magic_rule = false;
	}

RuleMatcher::~RuleMatcher()
	{
#ifdef MATCHER_PRINT_STATS
	DumpStats(stderr);
#endif
	Delete(root);

	for ( auto rule : rules )
		delete rule;
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

bool RuleMatcher::ReadFiles(const std::vector<SignatureFile>& files)
	{
#ifdef USE_PERFTOOLS_DEBUG
	HeapLeakChecker::Disabler disabler;
#endif

	parse_error = false;

	for ( auto f : files )
		{
		if ( ! f.full_path )
			f.full_path = util::find_file(f.file, util::zeek_path(), ".sig");

		// We mimic previous Zeek versions by temporarily setting the current
		// script location to the place where the loading happened. This
		// behavior was never documented, but seems worth not breaking as some
		// plugins ended up relying on it.
		Location orig_location = detail::GetCurrentLocation();
		detail::SetCurrentLocation(f.load_location);

		std::pair<int, std::optional<std::string>> rc = {-1, std::nullopt};
		rc.first = PLUGIN_HOOK_WITH_RESULT(
			HOOK_LOAD_FILE, HookLoadFile(zeek::plugin::Plugin::SIGNATURES, f.file, *f.full_path),
			-1);

		if ( rc.first < 0 )
			rc = PLUGIN_HOOK_WITH_RESULT(
				HOOK_LOAD_FILE_EXT,
				HookLoadFileExtended(zeek::plugin::Plugin::SIGNATURES, f.file, *f.full_path),
				std::make_pair(-1, std::nullopt));

		// Restore original location information.
		detail::SetCurrentLocation(orig_location);

		switch ( rc.first )
			{
			case -1:
				// No plugin in charge of this file.
				if ( f.full_path->empty() )
					{
					zeek::reporter->Error("failed to find file associated with @load-sigs %s",
					                      f.file.c_str());
					continue;
					}
				break;

			case 0:
				if ( ! zeek::reporter->Errors() )
					zeek::reporter->Error("Plugin reported error loading signatures %s",
					                      f.file.c_str());

				exit(1);
				break;

			case 1:
				if ( ! rc.second )
					// A plugin took care of it, just skip.
					continue;

				break;

			default:
				assert(false);
				break;
			}

		FILE* rules_in = nullptr;

		if ( rc.first == 1 )
			{
			// Parse code provided by plugin.
			assert(rc.second);
			rules_set_input_from_buffer(rc.second->data(), rc.second->size());
			}
		else
			{
			// Parse from file.
			rules_in = util::open_file(*f.full_path);

			if ( ! rules_in )
				{
				reporter->Error("Can't open signature file %s", f.file.c_str());
				return false;
				}

			rules_set_input_from_file(rules_in);
			}

		rules_line_number = 0;
		current_rule_file = f.full_path->c_str();
		rules_parse_input();

		if ( rules_in )
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
	if ( rules_by_id.find(rule->ID()) != rules_by_id.end() )
		{
		rules_error("rule defined twice");
		return;
		}

	rules.push_back(rule);
	rules_by_id[rule->ID()] = rule;
	}

void RuleMatcher::BuildRulesTree()
	{
	for ( const auto& rule : rules )
		{
		if ( ! rule->Active() )
			continue;

		const auto& pats = rule->patterns;

		if ( ! has_non_file_magic_rule )
			{
			if ( pats.length() > 0 )
				{
				for ( const auto& p : pats )
					{
					if ( p->type != Rule::FILE_MAGIC )
						{
						has_non_file_magic_rule = true;
						break;
						}
					}
				}
			else
				has_non_file_magic_rule = true;
			}

		rule->SortHdrTests();
		InsertRuleIntoTree(rule, 0, root, 0);
		}
	}

void RuleMatcher::InsertRuleIntoTree(Rule* r, int testnr, RuleHdrTest* dest, int level)
	{
	// Initialize the preconditions
	for ( const auto& pc : r->preconds )
		{
		auto entry = rules_by_id.find(pc->id);
		if ( entry == rules_by_id.end() )
			{
			rules_error(r, "unknown rule referenced");
			return;
			}

		pc->rule = entry->second;
		entry->second->dependents.push_back(r);
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

void RuleMatcher::BuildRegEx(RuleHdrTest* hdr_test, string_list* exprs, int_list* ids)
	{
	// For each type, get all patterns on this node.
	for ( Rule* r = hdr_test->pattern_rules; r; r = r->next )
		{
		for ( const auto& p : r->patterns )
			{
			exprs[p->type].push_back(p->pattern);
			ids[p->type].push_back(p->id);
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
				exprs[i].push_back(child_exprs[i][j]);
				ids[i].push_back(child_ids[i][j]);
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

void RuleMatcher::BuildPatternSets(RuleHdrTest::pattern_set_list* dst, const string_list& exprs,
                                   const int_list& ids)
	{
	assert(static_cast<size_t>(exprs.length()) == ids.size());

	// We build groups of at most sig_max_group_size regexps.

	string_list group_exprs;
	int_list group_ids;

	for ( int i = 0; i < exprs.length() + 1 /* sic! */; i++ )
		{
		if ( i < exprs.length() )
			{
			group_exprs.push_back(exprs[i]);
			group_ids.push_back(ids[i]);
			}

		if ( group_exprs.length() > sig_max_group_size || i == exprs.length() )
			{
			RuleHdrTest::PatternSet* set = new RuleHdrTest::PatternSet;
			set->re = new Specific_RE_Matcher(MATCH_EXACTLY, true);
			set->re->CompileSet(group_exprs, group_ids);
			set->patterns = group_exprs;
			set->ids = group_ids;
			dst->push_back(set);

			group_exprs.clear();
			group_ids.clear();
			}
		}
	}

// Get a 8/16/32-bit value from the given position in the packet header
static inline uint32_t getval(const u_char* data, int size)
	{
	switch ( size )
		{
		case 1:
			return *(uint8_t*)data;

		case 2:
			return ntohs(*(uint16_t*)data);

		case 4:
			return ntohl(*(uint32_t*)data);

		default:
			reporter->InternalError("illegal HdrTest size");
		}

	// Should not be reached.
	return 0;
	}

// Evaluate a value list (matches if at least one value matches).
template <typename FuncT>
static inline bool match_or(const maskedvalue_list& mvals, uint32_t v, FuncT comp)
	{
	// TODO: this could be a find_if
	for ( const auto& val : mvals )
		{
		if ( comp(v & val->mask, val->val) )
			return true;
		}
	return false;
	}

// Evaluate a prefix list (matches if at least one value matches).
template <typename FuncT>
static inline bool match_or(const vector<IPPrefix>& prefixes, const IPAddr& a, FuncT comp)
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
static inline bool match_not_and(const maskedvalue_list& mvals, uint32_t v, FuncT comp)
	{
	// TODO: this could be a find_if
	for ( const auto& val : mvals )
		{
		if ( comp(v & val->mask, val->val) )
			return false;
		}
	return true;
	}

// Evaluate a prefix list (doesn't match if any value matches).
template <typename FuncT>
static inline bool match_not_and(const vector<IPPrefix>& prefixes, const IPAddr& a, FuncT comp)
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

static inline bool compare(const maskedvalue_list& mvals, uint32_t v, RuleHdrTest::Comp comp)
	{
	switch ( comp )
		{
		case RuleHdrTest::EQ:
			return match_or(mvals, v, std::equal_to<uint32_t>());
			break;

		case RuleHdrTest::NE:
			return match_not_and(mvals, v, std::equal_to<uint32_t>());
			break;

		case RuleHdrTest::LT:
			return match_or(mvals, v, std::less<uint32_t>());
			break;

		case RuleHdrTest::GT:
			return match_or(mvals, v, std::greater<uint32_t>());
			break;

		case RuleHdrTest::LE:
			return match_or(mvals, v, std::less_equal<uint32_t>());
			break;

		case RuleHdrTest::GE:
			return match_or(mvals, v, std::greater_equal<uint32_t>());
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
	switch ( comp )
		{
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

	for ( const auto& set : root->psets[Rule::FILE_MAGIC] )
		{
		assert(set->re);
		RuleFileMagicState::Matcher* m = new RuleFileMagicState::Matcher;
		m->state = new RE_Match_State(set->re);
		state->matchers.push_back(m);
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
	for ( const auto& pattern : r->patterns )
		{
		if ( ams.find(pattern->id) == ams.end() )
			return false;

		// See if depth is satisfied.
		if ( matchpos > pattern->offset + pattern->depth )
			return false;

		// FIXME: How to check for offset ??? ###
		}

	DBG_LOG(DBG_RULES, "All patterns of rule satisfied");

	return true;
	}

RuleMatcher::MIME_Matches* RuleMatcher::Match(RuleFileMagicState* state, const u_char* data,
                                              uint64_t len, MIME_Matches* rval) const
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
		const char* s = util::fmt_bytes(reinterpret_cast<const char*>(data),
		                                min(40, static_cast<int>(len)));
		DBG_LOG(DBG_RULES, "Matching %s rules on |%s%s|", Rule::TypeToString(Rule::FILE_MAGIC), s,
		        len > 40 ? "..." : "");
		}
#endif

	bool newmatch = false;

	for ( const auto& m : state->matchers )
		{
		if ( m->state->Match(data, len, true, false, true) )
			newmatch = true;
		}

	if ( ! newmatch )
		return rval;

	DBG_LOG(DBG_RULES, "New pattern match found");

	AcceptingMatchSet accepted_matches;

	for ( const auto& m : state->matchers )
		{
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

	for ( set<Rule*>::const_iterator it = rule_matches.begin(); it != rule_matches.end(); ++it )
		{
		Rule* r = *it;

		for ( const auto& action : r->actions )
			{
			const RuleActionMIME* ram = dynamic_cast<const RuleActionMIME*>(action);

			if ( ! ram )
				continue;

			set<string>& ss = (*rval)[ram->GetStrength()];
			ss.insert(ram->GetMIME());
			}
		}

	return rval;
	}

RuleEndpointState* RuleMatcher::InitEndpoint(analyzer::Analyzer* analyzer, const IP_Hdr* ip,
                                             int caplen, RuleEndpointState* opposite,
                                             bool from_orig, analyzer::pia::PIA* pia)
	{
	RuleEndpointState* state = new RuleEndpointState(analyzer, from_orig, opposite, pia);

	rule_hdr_test_list tests;
	tests.push_back(root);

	loop_over_list(tests, h)
		{
		RuleHdrTest* hdr_test = tests[h];

		DBG_LOG(DBG_RULES, "HdrTest %d matches (%s%s)", hdr_test->id,
		        hdr_test->pattern_rules ? "+" : "-", hdr_test->pure_rules ? "+" : "-");

		// Current HdrTest node matches the packet, so remember it
		// if we have any rules on it.
		if ( hdr_test->pattern_rules || hdr_test->pure_rules )
			state->hdr_tests.push_back(hdr_test);

		// Evaluate all rules on this node which don't contain
		// any patterns.
		for ( Rule* r = hdr_test->pure_rules; r; r = r->next )
			if ( EvalRuleConditions(r, state, nullptr, 0, false) )
				ExecRuleActions(r, state, nullptr, 0, false);

		// If we're on or above the RE_level, we may have some
		// pattern matching to do.
		if ( hdr_test->level <= RE_level )
			{
			for ( int i = Rule::PAYLOAD; i < Rule::TYPES; ++i )
				{
				for ( const auto& set : hdr_test->psets[i] )
					{
					assert(set->re);

					auto* m = new RuleEndpointState::Matcher;
					m->state = new RE_Match_State(set->re);
					m->type = (Rule::PatternType)i;
					state->matchers.push_back(m);
					}
				}
			}

		if ( ip )
			{
			// Descend the RuleHdrTest tree further.
			for ( RuleHdrTest* h = hdr_test->child; h; h = h->sibling )
				{
				bool match = false;

				// Evaluate the header test.
				switch ( h->prot )
					{
					case RuleHdrTest::NEXT:
						match = compare(*h->vals, ip->NextProto(), h->comp);
						break;

					case RuleHdrTest::IP:
						if ( ! ip->IP4_Hdr() )
							continue;

						match = compare(*h->vals,
						                getval((const u_char*)ip->IP4_Hdr() + h->offset, h->size),
						                h->comp);
						break;

					case RuleHdrTest::IPv6:
						if ( ! ip->IP6_Hdr() )
							continue;

						match = compare(*h->vals,
						                getval((const u_char*)ip->IP6_Hdr() + h->offset, h->size),
						                h->comp);
						break;

					case RuleHdrTest::ICMP:
					case RuleHdrTest::ICMPv6:
					case RuleHdrTest::TCP:
					case RuleHdrTest::UDP:
						match = compare(*h->vals, getval(ip->Payload() + h->offset, h->size),
						                h->comp);
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
					tests.push_back(h);
				}
			}
		}
	// Save some memory.
	state->hdr_tests.resize(0);
	state->matchers.resize(0);

	// Send BOL to payload matchers.
	Match(state, Rule::PAYLOAD, (const u_char*)"", 0, true, false, false);

	return state;
	}

void RuleMatcher::Match(RuleEndpointState* state, Rule::PatternType type, const u_char* data,
                        int data_len, bool bol, bool eol, bool clear)
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
		const char* s = util::fmt_bytes((const char*)data, min(40, data_len));

		DBG_LOG(DBG_RULES, "Matching %s rules [%d,%d] on |%s%s|", Rule::TypeToString(type), bol,
		        eol, s, data_len > 40 ? "..." : "");
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
	for ( const auto& m : state->matchers )
		{
		if ( m->type == type && m->state->Match((const u_char*)data, data_len, bol, eol, clear) )
			newmatch = true;
		}

	// If no new match found, we're already done.
	if ( ! newmatch )
		return;

	DBG_LOG(DBG_RULES, "New pattern match found");

	AcceptingMatchSet accepted_matches;

	for ( const auto& m : state->matchers )
		{
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

	for ( set<Rule*>::const_iterator it = rule_matches.begin(); it != rule_matches.end(); ++it )
		{
		Rule* r = *it;

		DBG_LOG(DBG_RULES, "Accepted rule: %s", r->id);

		for ( const auto& h : state->hdr_tests )
			{
			DBG_LOG(DBG_RULES, "Checking for accepted rule on HdrTest %d", h->id);

			// Skip if rule does not belong to this node.
			if ( ! h->ruleset->Contains(r->Index()) )
				continue;

			DBG_LOG(DBG_RULES, "On current node");

			// Skip if rule already fired for this connection.
			if ( is_member_of(state->matched_rules, r->Index()) )
				continue;

			// Remember that all patterns have matched.
			if ( ! state->matched_by_patterns.is_member(r) )
				{
				state->matched_by_patterns.push_back(r);
				String* s = new String(data, data_len, false);
				state->matched_text.push_back(s);
				}

			DBG_LOG(DBG_RULES, "And has not already fired");
			// Eval additional conditions.
			if ( ! EvalRuleConditions(r, state, data, data_len, false) )
				continue;

			// Found a match.
			ExecRuleActions(r, state, data, data_len, false);
			}
		}
	}

void RuleMatcher::FinishEndpoint(RuleEndpointState* state)
	{
	// Send EOL to payload matchers.
	Match(state, Rule::PAYLOAD, (const u_char*)"", 0, false, true, false);

	// Some of the pure rules may match at the end of the connection,
	// although they have not matched at the beginning. So, we have
	// to test the candidates here.

	ExecPureRules(state, true);

	loop_over_list(state->matched_by_patterns, i)
		ExecRulePurely(state->matched_by_patterns[i], state->matched_text[i], state, true);
	}

void RuleMatcher::ExecPureRules(RuleEndpointState* state, bool eos)
	{
	for ( const auto& hdr_test : state->hdr_tests )
		{
		for ( Rule* r = hdr_test->pure_rules; r; r = r->next )
			ExecRulePurely(r, nullptr, state, eos);
		}
	}

bool RuleMatcher::ExecRulePurely(Rule* r, String* s, RuleEndpointState* state, bool eos)
	{
	if ( is_member_of(state->matched_rules, r->Index()) )
		return false;

	DBG_LOG(DBG_RULES, "Checking rule %s purely", r->ID());

	if ( EvalRuleConditions(r, state, nullptr, 0, eos) )
		{
		DBG_LOG(DBG_RULES, "MATCH!");

		if ( s )
			ExecRuleActions(r, state, s->Bytes(), s->Len(), eos);
		else
			ExecRuleActions(r, state, nullptr, 0, eos);

		return true;
		}

	return false;
	}

bool RuleMatcher::EvalRuleConditions(Rule* r, RuleEndpointState* state, const u_char* data, int len,
                                     bool eos)
	{
	DBG_LOG(DBG_RULES, "Evaluating conditions for rule %s", r->ID());

	// Check for other rules which have to match first.
	for ( const auto& pc : r->preconds )
		{
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
			if ( ! is_member_of(pc_state->matched_rules, pc->rule->Index()) )
				// Precond rule has not matched yet.
				return false;
			}
		else
			{
			// Only at eos can we decide about negated conditions.
			if ( ! eos )
				return false;

			if ( is_member_of(pc_state->matched_rules, pc->rule->Index()) )
				return false;
			}
		}

	for ( const auto& cond : r->conditions )
		if ( ! cond->DoMatch(r, state, data, len) )
			return false;

	DBG_LOG(DBG_RULES, "Conditions met: MATCH! %s", r->ID());
	return true;
	}

void RuleMatcher::ExecRuleActions(Rule* r, RuleEndpointState* state, const u_char* data, int len,
                                  bool eos)
	{
	if ( state->opposite && is_member_of(state->opposite->matched_rules, r->Index()) )
		// We have already executed the actions.
		return;

	state->matched_rules.push_back(r->Index());

	for ( const auto& action : r->actions )
		action->DoAction(r, state, data, len);

	// This rule may trigger some other rules; check them.
	for ( const auto& dep : r->dependents )
		{
		ExecRule(dep, state, eos);
		if ( state->opposite )
			ExecRule(dep, state->opposite, eos);
		}
	}

void RuleMatcher::ExecRule(Rule* rule, RuleEndpointState* state, bool eos)
	{
	// Nothing to do if it has already matched.
	if ( is_member_of(state->matched_rules, rule->Index()) )
		return;

	for ( const auto& h : state->hdr_tests )
		{
		// Is it on this HdrTest at all?
		if ( ! h->ruleset->Contains(rule->Index()) )
			continue;

		// Is it a pure rule?
		for ( Rule* r = h->pure_rules; r; r = r->next )
			if ( r == rule )
				{ // found, so let's evaluate it
				ExecRulePurely(rule, nullptr, state, eos);
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
	ExecPureRules(state, true);

	state->payload_size = -1;

	for ( const auto& matcher : state->matchers )
		matcher->state->Clear();
	}

void RuleMatcher::ClearFileMagicState(RuleFileMagicState* state) const
	{
	for ( const auto& matcher : state->matchers )
		matcher->state->Clear();
	}

void RuleMatcher::PrintDebug()
	{
	for ( const auto& rule : rules )
		rule->PrintDebug();

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

			fprintf(stderr, "[%d patterns in %s group %d from %zu rules]\n", set->patterns.length(),
			        Rule::TypeToString((Rule::PatternType)i), j, set->ids.size());
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
		for ( const auto& set : hdr_test->psets[i] )
			{
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

void RuleMatcher::DumpStats(File* f)
	{
	Stats stats;
	GetStats(&stats);

	f->Write(util::fmt("%.6f computed dfa states = %d; classes = ??; "
	                   "computed trans. = %d; matchers = %d; mem = %d\n",
	                   run_state::network_time, stats.dfa_states, stats.computed, stats.matchers,
	                   stats.mem));
	f->Write(util::fmt("%.6f DFA cache hits = %d; misses = %d\n", run_state::network_time,
	                   stats.hits, stats.misses));

	DumpStateStats(f, root);
	}

void RuleMatcher::DumpStateStats(File* f, RuleHdrTest* hdr_test)
	{
	if ( ! hdr_test )
		return;

	for ( int i = 0; i < Rule::TYPES; i++ )
		{
		loop_over_list(hdr_test->psets[i], j)
			{
			RuleHdrTest::PatternSet* set = hdr_test->psets[i][j];
			assert(set->re);

			f->Write(util::fmt("%.6f %d DFA states in %s group %d from sigs ",
			                   run_state::network_time, set->re->DFA()->NumStates(),
			                   Rule::TypeToString((Rule::PatternType)i), j));

			for ( const auto& id : set->ids )
				{
				Rule* r = Rule::rule_table[id - 1];
				f->Write(util::fmt("%s ", r->ID()));
				}

			f->Write("\n");
			}
		}

	for ( RuleHdrTest* h = hdr_test->child; h; h = h->sibling )
		DumpStateStats(f, h);
	}

static Val* get_zeek_val(const char* label)
	{
	auto id = lookup_ID(label, GLOBAL_MODULE_NAME, false);
	if ( ! id )
		{
		rules_error("unknown script-level identifier", label);
		return nullptr;
		}

	return id->GetVal().get();
	}

// Converts an atomic Val and appends it to the list.  For subnet types,
// if the prefix_vector param isn't null, appending to that is preferred
// over appending to the masked val list.
static bool val_to_maskedval(Val* v, maskedvalue_list* append_to, vector<IPPrefix>* prefix_vector)
	{
	MaskedValue* mval = new MaskedValue;

	switch ( v->GetType()->Tag() )
		{
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
				const uint32_t* n;
				uint32_t m[4];
				v->AsSubNet().Prefix().GetBytes(&n);
				v->AsSubNetVal()->Mask().CopyIPv6(m);

				for ( unsigned int i = 0; i < 4; ++i )
					m[i] = ntohl(m[i]);

				bool is_v4_mask = m[0] == 0xffffffff && m[1] == m[0] && m[2] == m[0];

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

	append_to->push_back(mval);

	return true;
	}

void id_to_maskedvallist(const char* id, maskedvalue_list* append_to,
                         vector<IPPrefix>* prefix_vector)
	{
	Val* v = get_zeek_val(id);
	if ( ! v )
		return;

	if ( v->GetType()->Tag() == TYPE_TABLE )
		{
		auto lv = v->AsTableVal()->ToPureListVal();

		for ( const auto& val : lv->Vals() )
			if ( ! val_to_maskedval(val.get(), append_to, prefix_vector) )
				return;
		}

	else
		val_to_maskedval(v, append_to, prefix_vector);
	}

char* id_to_str(const char* id)
	{
	const String* src;
	char* dst;

	Val* v = get_zeek_val(id);
	if ( ! v )
		goto error;

	if ( v->GetType()->Tag() != TYPE_STRING )
		{
		rules_error("Identifier must refer to string");
		goto error;
		}

	src = v->AsString();
	dst = new char[src->Len() + 1];
	memcpy(dst, src->Bytes(), src->Len());
	*(dst + src->Len()) = '\0';
	return dst;

error:
	char* dummy = util::copy_string("<error>");
	return dummy;
	}

uint32_t id_to_uint(const char* id)
	{
	Val* v = get_zeek_val(id);
	if ( ! v )
		return 0;

	TypeTag t = v->GetType()->Tag();

	if ( t == TYPE_BOOL || t == TYPE_COUNT || t == TYPE_ENUM || t == TYPE_INT || t == TYPE_PORT )
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

		orig_match_state = rule_matcher->InitEndpoint(analyzer, ip, caplen, resp_match_state,
		                                              from_orig, pia);
		}

	else
		{
		if ( resp_match_state )
			{
			rule_matcher->FinishEndpoint(resp_match_state);
			delete resp_match_state;
			}

		resp_match_state = rule_matcher->InitEndpoint(analyzer, ip, caplen, orig_match_state,
		                                              from_orig, pia);
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

	orig_match_state = resp_match_state = nullptr;
	}

void RuleMatcherState::Match(Rule::PatternType type, const u_char* data, int data_len,
                             bool from_orig, bool bol, bool eol, bool clear)
	{
	if ( ! rule_matcher )
		return;

	rule_matcher->Match(from_orig ? orig_match_state : resp_match_state, type, data, data_len, bol,
	                    eol, clear);
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

	} // namespace zeek::detail
