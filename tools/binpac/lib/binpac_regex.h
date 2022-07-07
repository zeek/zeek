#ifndef binpac_regex_h
#define binpac_regex_h

#include "zeek/RE.h"

#include "binpac.h"

namespace zeek
	{
class RE_Matcher;
	}

namespace binpac
	{

// Must be called before any binpac functionality is used.
//
// Note, this must be declared/defined here, and inline, because the RE
// functionality can only be used when compiling from inside Zeek.
// A copy is made of any FlowBuffer policy struct data passed.
inline void init(FlowBuffer::Policy* fbp = 0);

// Internal vector recording not yet compiled matchers.
extern std::vector<zeek::RE_Matcher*>* uncompiled_re_matchers;

class RegExMatcher
	{
public:
	RegExMatcher(const char* pattern) : pattern_(pattern)
		{
		if ( ! uncompiled_re_matchers )
			uncompiled_re_matchers = new std::vector<zeek::RE_Matcher*>;

		re_matcher_ = new zeek::RE_Matcher(pattern_.c_str());
		uncompiled_re_matchers->push_back(re_matcher_);
		}

	~RegExMatcher() { delete re_matcher_; }

	// Returns the length of longest match, or -1 on mismatch.
	int MatchPrefix(const_byteptr data, int len) { return re_matcher_->MatchPrefix(data, len); }

private:
	friend void ::binpac::init(FlowBuffer::Policy*);

	// Function, and state, for compiling matchers.
	static void init();

	string pattern_;
	zeek::RE_Matcher* re_matcher_;
	};

inline void RegExMatcher::init()
	{
	if ( ! uncompiled_re_matchers )
		return;

	for ( size_t i = 0; i < uncompiled_re_matchers->size(); ++i )
		{
		if ( ! (*uncompiled_re_matchers)[i]->Compile() )
			{
			fprintf(stderr, "binpac: cannot compile regular expression\n");
			exit(1);
			}
		}

	uncompiled_re_matchers->clear();
	}

inline void init(FlowBuffer::Policy* fbp)
	{
	RegExMatcher::init();

	if ( fbp )
		FlowBuffer::init(*fbp);
	}

	} // namespace binpac

#endif // binpac_regex_h
