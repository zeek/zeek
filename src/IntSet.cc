#include "zeek/IntSet.h"

#include "zeek/zeek-config.h"

#include <cstring>

namespace zeek::detail
	{

void IntSet::Expand(unsigned int i)
	{
	unsigned int newsize = i / 8 + 1;
	unsigned char* newset = new unsigned char[newsize];

	memset(newset, 0, newsize);
	memcpy(newset, set, size);

	delete[] set;
	size = newsize;
	set = newset;
	}

	} // namespace zeek::detail
