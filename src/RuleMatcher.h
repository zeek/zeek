#pragma once

#include <sys/types.h> // for u_char
#include <climits>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "zeek/CCL.h"
#include "zeek/RE.h"
#include "zeek/Rule.h"
#include "zeek/ScannedFile.h"
#include "zeek/plugin/Manager.h"

//#define MATCHER_PRINT_STATS

// Parser interface:

extern void rules_error(const char* msg);
extern void rules_error(const char* msg, const char* addl);
extern void rules_error(zeek::detail::Rule* id, const char* msg);
extern int rules_lex(void);
extern int rules_parse(void);
extern "C" int rules_wrap(void);
extern int rules_line_number;
extern const char* current_rule_file;

namespace zeek
	{

class File;
class IP_Hdr;
class IPPrefix;
class Val;

namespace analyzer
	{
class Analyzer;
	}
namespace analyzer::pia
	{
class PIA;
	}

namespace detail
	{

class RE_Match_State;
class Specific_RE_Matcher;
class RuleMatcher;
class IntSet;

extern RuleMatcher* rule_matcher;

// RuleHdrTest and associated things:

// Given a header expression like "ip[offset:len] & mask = val", we parse
// it into a Range and a MaskedValue.
struct Range
	{
	uint32_t offset;
	uint32_t len;
	};

struct MaskedValue
	{
	uint32_t val;
	uint32_t mask;
	};

using maskedvalue_list = PList<MaskedValue>;
using string_list = PList<char>;
using bstr_list = PList<String>;

// Get values from Zeek's script-level variables.
extern void id_to_maskedvallist(const char* id, maskedvalue_list* append_to,
                                std::vector<IPPrefix>* prefix_vector = nullptr);
extern char* id_to_str(const char* id);
extern uint32_t id_to_uint(const char* id);

class RuleHdrTest
	{
public:
	// Note: Adapt RuleHdrTest::PrintDebug() when changing these enums.
	enum Comp
		{
		LE,
		GE,
		LT,
		GT,
		EQ,
		NE
		};
	enum Prot
		{
		NOPROT,
		IP,
		IPv6,
		ICMP,
		ICMPv6,
		TCP,
		UDP,
		NEXT,
		IPSrc,
		IPDst
		};

	RuleHdrTest(Prot arg_prot, uint32_t arg_offset, uint32_t arg_size, Comp arg_comp,
	            maskedvalue_list* arg_vals);
	RuleHdrTest(Prot arg_prot, Comp arg_comp, std::vector<IPPrefix> arg_v);
	~RuleHdrTest();

	void PrintDebug();

private:
	// The constructor does not copy those attributes which are set
	// by RuleMatcher::BuildRulesTree() (see below).
	RuleHdrTest(RuleHdrTest& h);
	// should be const, but lists don't have const version

	// Likewise, the operator== checks only for same test semantics.
	bool operator==(const RuleHdrTest& h);

	Prot prot;
	Comp comp;
	maskedvalue_list* vals;
	std::vector<IPPrefix> prefix_vals; // for use with IPSrc/IPDst comparisons
	uint32_t offset;
	uint32_t size;

	uint32_t id; // For debugging, each HdrTest gets an unique ID
	static uint32_t idcounter;
	int32_t level; // level within the tree

	// The following are all set by RuleMatcher::BuildRulesTree().
	friend class RuleMatcher;

	struct PatternSet
		{
		PatternSet() : re() { }

		// If we're above the 'RE_level' (see RuleMatcher), this
		// expr contains all patterns on this node. If we're on
		// 'RE_level', it additionally contains all patterns
		// of any of its children.
		Specific_RE_Matcher* re;

		// All the patterns and their rule indices.
		string_list patterns;
		int_list ids; // (only needed for debugging)
		};

	using pattern_set_list = PList<PatternSet>;
	pattern_set_list psets[Rule::TYPES];

	// List of rules belonging to this node.
	Rule* pattern_rules; // rules w/ at least one pattern of any type
	Rule* pure_rules; // rules containing no patterns at all

	IntSet* ruleset; // set of all rules belonging to this node
	                 // (for fast membership test)

	RuleHdrTest* sibling; // linkage within HdrTest tree
	RuleHdrTest* child;
	};

using rule_hdr_test_list = PList<RuleHdrTest>;

// RuleEndpointState keeps the per-stream matching state of one
// connection endpoint.
class RuleEndpointState
	{
public:
	~RuleEndpointState();

	analyzer::Analyzer* GetAnalyzer() const { return analyzer; }
	bool IsOrig() { return is_orig; }

	// For flipping roles.
	void FlipIsOrig() { is_orig = ! is_orig; }

	// Returns the size of the first non-empty chunk of
	//   data feed into the RULE_PAYLOAD matcher.
	// Returns 0 zero iff only empty chunks have been fed.
	// Returns -1 if no chunk has been fed yet at all.
	int PayloadSize() { return payload_size; }

	analyzer::pia::PIA* PIA() const { return pia; }

private:
	friend class RuleMatcher;

	// Constructor is private; use RuleMatcher::InitEndpoint()
	// for creating an instance.
	RuleEndpointState(analyzer::Analyzer* arg_analyzer, bool arg_is_orig,
	                  RuleEndpointState* arg_opposite, analyzer::pia::PIA* arg_PIA);

	struct Matcher
		{
		RE_Match_State* state;
		Rule::PatternType type;
		};

	using matcher_list = PList<Matcher>;

	analyzer::Analyzer* analyzer;
	RuleEndpointState* opposite;
	analyzer::pia::PIA* pia;

	matcher_list matchers;
	rule_hdr_test_list hdr_tests;

	// The follow tracks which rules for which all patterns have matched,
	// and in a parallel list the (first instance of the) corresponding
	// matched text.
	rule_list matched_by_patterns;
	bstr_list matched_text;

	int payload_size;
	bool is_orig;

	int_list matched_rules; // Rules for which all conditions have matched
	};

/**
 * A state object used for matching file magic signatures.
 */
class RuleFileMagicState
	{
	friend class RuleMatcher;

public:
	~RuleFileMagicState();

private:
	// Ctor is private; use RuleMatcher::InitFileMagic() for
	// instantiation.
	RuleFileMagicState() { }

	struct Matcher
		{
		RE_Match_State* state;
		};

	using matcher_list = PList<Matcher>;
	matcher_list matchers;
	};

// RuleMatcher is the main class which builds up the data structures
// and performs the actual matching.

class RuleMatcher
	{
public:
	// Argument is tree level on which we build combined regexps
	// (Level 0 is root).
	RuleMatcher(int RE_level = 4);
	~RuleMatcher();

	// Parse the given files and built up data structures.
	bool ReadFiles(const std::vector<SignatureFile>& files);

	/**
	 * Inititialize a state object for matching file magic signatures.
	 * @return A state object that can be used for file magic mime type
	 *         identification.
	 */
	RuleFileMagicState* InitFileMagic() const;

	/**
	 * Data structure containing a set of matching file magic signatures.
	 * Ordered from greatest to least strength.  Matches of the same strength
	 * will be in the set in lexicographic order of the MIME type string.
	 */
	using MIME_Matches = std::map<int, std::set<std::string>, std::greater<int>>;

	/**
	 * Matches a chunk of data against file magic signatures.
	 * @param state A state object previously returned from
	 *              RuleMatcher::InitFileMagic()
	 * @param data Chunk of data to match signatures against.
	 * @param len Length of \a data in bytes.
	 * @param matches An optional pre-existing match result object to
	 *                modify with additional matches.  If it's a null
	 *                pointer, one will be instantiated and returned from
	 *                this method.
	 * @return The results of the signature matching.
	 */
	MIME_Matches* Match(RuleFileMagicState* state, const u_char* data, uint64_t len,
	                    MIME_Matches* matches = nullptr) const;

	/**
	 * Resets a state object used with matching file magic signatures.
	 * @param state The state object to reset to an initial condition.
	 */
	void ClearFileMagicState(RuleFileMagicState* state) const;

	// Initialize the matching state for a endpoint of a connection based on
	// the given packet (which should be the first packet encountered for
	// this endpoint). If the matching is triggered by an PIA, a pointer to
	// it needs to be given.
	RuleEndpointState* InitEndpoint(analyzer::Analyzer* analyzer, const IP_Hdr* ip, int caplen,
	                                RuleEndpointState* opposite, bool is_orig,
	                                analyzer::pia::PIA* pia);

	// Finish matching for this stream.
	void FinishEndpoint(RuleEndpointState* state);

	// Perform the actual pattern matching on the given data.
	// bol/eol should be set to false for type Rule::PAYLOAD; they're
	// deduced automatically.
	void Match(RuleEndpointState* state, Rule::PatternType type, const u_char* data, int data_len,
	           bool bol, bool eol, bool clear);

	// Reset the state of the pattern matcher for this endpoint.
	void ClearEndpointState(RuleEndpointState* state);

	void PrintDebug();

	// Interface to parser
	void AddRule(Rule* rule);
	void SetParseError() { parse_error = true; }

	bool HasNonFileMagicRule() const { return has_non_file_magic_rule; }

	// Interface to for getting some statistics
	struct Stats
		{
		unsigned int matchers; // # distinct RE matchers

		// NFA states across all matchers.
		unsigned int nfa_states;

		// # DFA states across all matchers
		unsigned int dfa_states;
		unsigned int computed; // # computed DFA state transitions
		unsigned int mem; // #  bytes used by DFA states

		// # cache hits (sampled, multiply by MOVE_TO_FRONT_SAMPLE_SIZE)
		unsigned int hits;
		unsigned int misses; // # cache misses
		};

	Val* BuildRuleStateValue(const Rule* rule, const RuleEndpointState* state) const;

	void GetStats(Stats* stats, RuleHdrTest* hdr_test = nullptr);
	void DumpStats(File* f);

private:
	// Delete node and all children.
	void Delete(RuleHdrTest* node);

	// Build tree containing all added rules.
	void BuildRulesTree();

	// Insert one rule into the current tree.
	void InsertRuleIntoTree(Rule* r, int testnr, RuleHdrTest* dest, int level);

	// Traverse tree building the combined regular expressions.
	void BuildRegEx(RuleHdrTest* hdr_test, string_list* exprs, int_list* ids);

	// Build groups of regular epxressions.
	void BuildPatternSets(RuleHdrTest::pattern_set_list* dst, const string_list& exprs,
	                      const int_list& ids);

	// Check an arbitrary rule if it's satisfied right now.
	// eos signals end of stream
	void ExecRule(Rule* rule, RuleEndpointState* state, bool eos);

	// Evaluate all rules which do not depend on any matched patterns.
	void ExecPureRules(RuleEndpointState* state, bool eos);

	// Eval a rule under the assumption that all its patterns
	// have already matched.  s holds the text the rule matched,
	// or nil if N/A.
	bool ExecRulePurely(Rule* r, String* s, RuleEndpointState* state, bool eos);

	// Execute the actions associated with a rule.
	void ExecRuleActions(Rule* r, RuleEndpointState* state, const u_char* data, int len, bool eos);

	// Evaluate all rule conditions except patterns and "header".
	bool EvalRuleConditions(Rule* r, RuleEndpointState* state, const u_char* data, int len,
	                        bool eos);

	void PrintTreeDebug(RuleHdrTest* node);

	void DumpStateStats(File* f, RuleHdrTest* hdr_test);

	static bool AllRulePatternsMatched(const Rule* r, MatchPos matchpos,
	                                   const AcceptingMatchSet& ams);

	int RE_level;
	bool has_non_file_magic_rule;
	bool parse_error;
	RuleHdrTest* root;
	rule_list rules;
	rule_dict rules_by_id;
	};

// Keeps bi-directional matching-state.
class RuleMatcherState
	{
public:
	RuleMatcherState() { orig_match_state = resp_match_state = nullptr; }
	~RuleMatcherState()
		{
		delete orig_match_state;
		delete resp_match_state;
		}

	// ip may be nil.
	void InitEndpointMatcher(analyzer::Analyzer* analyzer, const IP_Hdr* ip, int caplen,
	                         bool from_orig, analyzer::pia::PIA* pia = nullptr);

	// bol/eol should be set to false for type Rule::PAYLOAD; they're
	// deduced automatically.
	void Match(Rule::PatternType type, const u_char* data, int data_len, bool from_orig, bool bol,
	           bool eol, bool clear_state);

	void FinishEndpointMatcher();
	void ClearMatchState(bool orig);

	bool MatcherInitialized(bool orig) { return orig ? orig_match_state : resp_match_state; }

private:
	RuleEndpointState* orig_match_state;
	RuleEndpointState* resp_match_state;
	};

	} // namespace detail
	} // namespace zeek
