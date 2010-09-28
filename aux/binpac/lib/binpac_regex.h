#ifndef binpac_regex_h
#define binpac_regex_h

#include "binpac.h"
#include "RE.h"

class RE_Matcher;

namespace binpac
{

class RegExMatcher {
public:
	RegExMatcher(const char *pattern)
		: pattern_(pattern)
		{
		re_matcher_ = 0;
		}

	~RegExMatcher()
		{
		delete re_matcher_;
		}

	// Returns the length of longest match, or -1 on mismatch.
	int MatchPrefix(const_byteptr data, int len)
		{
		if ( ! re_matcher_ )
			{
			re_matcher_ = new RE_Matcher(pattern_.c_str());
			re_matcher_->Compile();
			}
		return re_matcher_->MatchPrefix(data, len);
		}

private:
	string pattern_;
	RE_Matcher *re_matcher_;
};

}  // namespace binpac

#endif  // binpac_regex_h
