#ifndef FILE_ANALYSIS_FILEREASSEMBLER_H
#define FILE_ANALYSIS_FILEREASSEMBLER_H

#include "Reassem.h"
#include "File.h"

class BroFile;
class Connection;

namespace file_analysis {

class File;

//const int STOP_ON_GAP = 1;
//const int PUNT_ON_PARTIAL = 1;

class FileReassembler : public Reassembler {
public:

	FileReassembler(File* f, uint64 starting_offset);
	virtual ~FileReassembler();

	void Done();
	uint64 GetFirstBlockOffset() { return blocks->seq; }

	// Checks if we have delivered all contents that we can possibly
	// deliver for this endpoint.
	void CheckEOF();

protected:
	FileReassembler()	{ }

	DECLARE_SERIAL(FileReassembler);

	void Undelivered(uint64 up_to_seq);
	void BlockInserted(DataBlock* b);
	void Overlap(const u_char* b1, const u_char* b2, uint64 n);

	unsigned int had_gap:1;
	unsigned int did_EOF:1;
	unsigned int skip_deliveries:1;
	File* the_file;
};

} // namespace analyzer::* 

#endif
