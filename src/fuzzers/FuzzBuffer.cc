#if !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include <string.h>

#include "FuzzBuffer.h"

bool zeek::FuzzBuffer::Valid() const
	{
	if ( end - begin < PKT_MAGIC_LEN + 2 )
		return false;

	if ( memcmp(begin, PKT_MAGIC, PKT_MAGIC_LEN) != 0)
		return false;

	return true;
	}

int zeek::FuzzBuffer::Next(const unsigned char** chunk, size_t* len, bool* is_orig)
	{
	if ( begin == end )
		{
		*chunk = nullptr;
		*len = 0;
		return 0;
		}

	auto pos = (const unsigned char*)memmem(begin, end - begin,
	                                        PKT_MAGIC, PKT_MAGIC_LEN);

	if ( ! pos )
		return -1;

	begin += PKT_MAGIC_LEN;
	auto remaining = end - begin;

	if ( remaining < 2 )
		return -2;

	*is_orig = begin[0] & 0x01;
	begin += 1;

	*chunk = begin;

	auto next = (const unsigned char*)memmem(begin, end - begin,
	                                         PKT_MAGIC, PKT_MAGIC_LEN);

	if ( next )
		begin = next;
	else
		begin = end;

	*len = begin - *chunk;
	return 0;
	}
