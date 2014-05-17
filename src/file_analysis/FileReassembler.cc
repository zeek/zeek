
#include "FileReassembler.h"
#include "File.h"


namespace file_analysis {

class File;

FileReassembler::FileReassembler(File *f, uint64 starting_offset)
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

	for ( DataBlock* b = start_block;
	      b && seq_delta(b->seq, last_reassem_seq) <= 0; b = b->next )
		{
		if ( b->seq == last_reassem_seq )
			{ // New stuff.
			int len = b->Size();
			int seq = last_reassem_seq;
			the_file->DeliverStream(b->block, len);
			last_reassem_seq += len;
			}
		}
	}

void FileReassembler::Undelivered(uint64 up_to_seq)
	{
	// Not doing anything here yet.
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
