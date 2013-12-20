
#include "FileReassembler.h"
#include "File.h"


namespace file_analysis {

class File;

FileReassembler::FileReassembler(File *f, int starting_offset)
	: Reassembler(starting_offset), the_file(f)
	{
	}

FileReassembler::~FileReassembler()
	{
	}

void FileReassembler::BlockInserted(DataBlock* start_block)
	{
	if ( seq_delta(start_block->seq, last_reassem_seq) > 0 ||
	     seq_delta(start_block->upper, last_reassem_seq) <= 0 )
		return;


	// We've filled a leading hole.  Deliver as much as possible.
	// Note that the new block may include both some old stuff
	// and some new stuff.  AddAndCheck() will have split the
	// new stuff off into its own block(s), but in the following
	// loop we have to take care not to deliver already-delivered
	// data.
	for ( DataBlock* b = start_block;
	      b && seq_delta(b->seq, last_reassem_seq) <= 0; b = b->next )
		{
		if ( b->seq == last_reassem_seq )
			{ // New stuff.
			int len = b->Size();
			int seq = last_reassem_seq;
			last_reassem_seq += len;
			the_file->DataIn(b->block, len, seq);
			}
		}

	//CheckEOF();
	}

void FileReassembler::Undelivered(int up_to_seq)
	{
	//reporter->Warning("should probably do something here (file reassembler undelivered)\n");
	}

void FileReassembler::Overlap(const u_char* b1, const u_char* b2, int n)
	{
	//reporter->Warning("should probably do something here (file reassembler overlap)\n");
	}


} // end file_analysis
