
#include "FileReassembler.h"
#include "File.h"


namespace file_analysis {

class File;

FileReassembler::FileReassembler(File *f, uint64 starting_offset)
	: Reassembler(starting_offset), the_file(f), flushing(false)
	{
	}

FileReassembler::FileReassembler()
	: Reassembler(), the_file(0), flushing(false)
	{
	}

FileReassembler::~FileReassembler()
	{
	}

uint64 FileReassembler::Flush()
	{
	if ( flushing )
		return 0;

	if ( last_block )
		{
		// This is expected to call back into FileReassembler::Undelivered().
		flushing = true;
		uint64 rval = TrimToSeq(last_block->upper);
		flushing = false;
		return rval;
		}

	return 0;
	}

uint64 FileReassembler::FlushTo(uint64 sequence)
	{
	if ( flushing )
		return 0;

	flushing = true;
	uint64 rval = TrimToSeq(sequence);
	flushing = false;
	last_reassem_seq = sequence;
	return rval;
	}

void FileReassembler::BlockInserted(DataBlock* start_block)
	{
	if ( start_block->seq > last_reassem_seq ||
	     start_block->upper <= last_reassem_seq )
		return;

	for ( DataBlock* b = start_block;
	      b && b->seq <= last_reassem_seq; b = b->next )
		{
		if ( b->seq == last_reassem_seq )
			{ // New stuff.
			uint64 len = b->Size();
			last_reassem_seq += len;
			the_file->DeliverStream(b->block, len);
			}
		}

	// Throw out forwarded data
	TrimToSeq(last_reassem_seq);
	}

void FileReassembler::Undelivered(uint64 up_to_seq)
	{
	// If we have blocks that begin below up_to_seq, deliver them.
	DataBlock* b = blocks;

	while ( b )
		{
		if ( b->seq < last_reassem_seq )
			{
			// Already delivered this block.
			b = b->next;
			continue;
			}

		if ( b->seq >= up_to_seq )
			// Block is beyond what we need to process at this point.
			break;

		uint64 gap_at_seq = last_reassem_seq;
		uint64 gap_len = b->seq - last_reassem_seq;
		the_file->Gap(gap_at_seq, gap_len);
		last_reassem_seq += gap_len;
		BlockInserted(b);
		// Inserting a block may cause trimming of what's buffered,
		// so have to assume 'b' is invalid, hence re-assign to start.
		b = blocks;
		}

	if ( up_to_seq > last_reassem_seq )
		{
		the_file->Gap(last_reassem_seq, up_to_seq - last_reassem_seq);
		last_reassem_seq = up_to_seq;
		}
	}

void FileReassembler::Overlap(const u_char* b1, const u_char* b2, uint64 n)
	{
	// Not doing anything here yet.
	}

IMPLEMENT_SERIAL(FileReassembler, SER_FILE_REASSEMBLER);

bool FileReassembler::DoSerialize(SerialInfo* info) const
	{
	reporter->InternalError("FileReassembler::DoSerialize not implemented");
	return false; // Cannot be reached.
	}

bool FileReassembler::DoUnserialize(UnserialInfo* info)
	{
	reporter->InternalError("FileReassembler::DoUnserialize not implemented");
	return false; // Cannot be reached.
	}

} // end file_analysis
