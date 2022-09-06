#include <zeek/CloneState.h>
#include <zeek/Val.h>

using namespace zeek;

ValPtr detail::CloneState::NewClone(Val* src, ValPtr dst)
	{
	clones.insert(std::make_pair(src, dst.get()));
	return dst;
	}
