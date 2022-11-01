#if ! defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "zeek/fuzzers/FuzzBuffer.h"

#ifdef _MSC_VER
#include <mem.h>
#endif

#include <cstring>

namespace zeek::detail
	{

bool FuzzBuffer::Valid(int chunk_count_limit) const
	{
	if ( end - begin < PKT_MAGIC_LEN + 2 )
		return false;

	if ( memcmp(begin, PKT_MAGIC, PKT_MAGIC_LEN) != 0 )
		return false;

	if ( ExceedsChunkLimit(chunk_count_limit) )
		return false;

	return true;
	}

int FuzzBuffer::ChunkCount(int chunk_count_limit) const
	{
	auto pos = begin;
	int chunks = 0;

	while ( pos < end && (chunks < chunk_count_limit || chunk_count_limit == 0) )
		{
		pos = (const unsigned char*)memmem(pos, end - pos, PKT_MAGIC, PKT_MAGIC_LEN);
		if ( ! pos )
			break;

		pos += PKT_MAGIC_LEN + 1;
		chunks++;
		}

	return chunks;
	}

std::optional<FuzzBuffer::Chunk> FuzzBuffer::Next()
	{
	if ( begin == end )
		return {};

	auto pos = (const unsigned char*)memmem(begin, end - begin, PKT_MAGIC, PKT_MAGIC_LEN);

	if ( ! pos )
		return {};

	begin += PKT_MAGIC_LEN;
	auto remaining = end - begin;

	if ( remaining < 2 )
		return {};

	Chunk rval;
	rval.is_orig = begin[0] & 0x01;
	begin += 1;

	auto chunk_begin = begin;

	auto next = (const unsigned char*)memmem(begin, end - begin, PKT_MAGIC, PKT_MAGIC_LEN);

	if ( next )
		begin = next;
	else
		begin = end;

	rval.size = begin - chunk_begin;

	if ( rval.size )
		{
		// The point of allocating a new buffer here is to better detect
		// analyzers that may over-read within a chunk  -- ASan wouldn't
		// complain if that happens to land within the full input buffer
		// provided by the fuzzing engine, but will if we allocate a new buffer
		// for each chunk.
		rval.data = std::make_unique<unsigned char[]>(rval.size);
		memcpy(rval.data.get(), chunk_begin, rval.size);
		return {std::move(rval)};
		}

	return {};
	}

	} // namespace zeek::detail
