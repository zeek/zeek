// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/FileReassembler.h"
#include "zeek/file_analysis/File.h"

namespace zeek::file_analysis {

class File;

FileReassembler::FileReassembler(File *f, uint64_t starting_offset)
	: Reassembler(starting_offset, REASSEM_FILE), the_file(f), flushing(false)
	{
	}

uint64_t FileReassembler::Flush()
	{
	if ( flushing )
		return 0;

	if ( block_list.Empty() )
		return 0;

	const auto& last_block = block_list.LastBlock();

	// This is expected to call back into FileReassembler::Undelivered().
	flushing = true;
	uint64_t rval = TrimToSeq(last_block.upper);
	flushing = false;
	return rval;
	}

uint64_t FileReassembler::FlushTo(uint64_t sequence)
	{
	if ( flushing )
		return 0;

	flushing = true;
	uint64_t rval = TrimToSeq(sequence);
	flushing = false;
	last_reassem_seq = sequence;
	return rval;
	}

void FileReassembler::BlockInserted(DataBlockMap::const_iterator it)
	{
	const auto& start_block = it->second;

	if ( start_block.seq > last_reassem_seq ||
	     start_block.upper <= last_reassem_seq )
		return;

	while ( it != block_list.End() )
		{
		const auto& b = it->second;

		if ( b.seq > last_reassem_seq )
			break;

		if ( b.seq == last_reassem_seq )
			{ // New stuff.
			uint64_t len = b.Size();
			last_reassem_seq += len;
			the_file->DeliverStream(b.block, len);
			}

		++it;
		}

	// Throw out forwarded data
	TrimToSeq(last_reassem_seq);
	}

void FileReassembler::Undelivered(uint64_t up_to_seq)
	{
	// If we have blocks that begin below up_to_seq, deliver them.
	auto it = block_list.Begin();

	while ( it != block_list.End() )
		{
		const auto& b = it->second;

		if ( b.seq < last_reassem_seq )
			{
			// Already delivered this block.
			++it;
			continue;
			}

		if ( b.seq >= up_to_seq )
			// Block is beyond what we need to process at this point.
			break;

		uint64_t gap_at_seq = last_reassem_seq;
		uint64_t gap_len = b.seq - last_reassem_seq;
		the_file->Gap(gap_at_seq, gap_len);
		last_reassem_seq += gap_len;
		BlockInserted(it);
		// Inserting a block may cause trimming of what's buffered,
		// so have to assume 'b' is invalid, hence re-assign to start.
		it = block_list.Begin();
		}

	if ( up_to_seq > last_reassem_seq )
		{
		the_file->Gap(last_reassem_seq, up_to_seq - last_reassem_seq);
		last_reassem_seq = up_to_seq;
		}
	}

void FileReassembler::Overlap(const u_char* b1, const u_char* b2, uint64_t n)
	{
	// Not doing anything here yet.
	}
} // end file_analysis
