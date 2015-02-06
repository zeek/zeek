#ifndef FILE_ANALYSIS_FILEREASSEMBLER_H
#define FILE_ANALYSIS_FILEREASSEMBLER_H

#include "Reassem.h"
#include "File.h"

class BroFile;
class Connection;

namespace file_analysis {

class File;

class FileReassembler : public Reassembler {
public:

	FileReassembler(File* f, uint64 starting_offset);
	virtual ~FileReassembler();

	void Done();

	// Checks if we have delivered all contents that we can possibly
	// deliver for this endpoint.
	void CheckEOF();

	/**
	 * Discards all contents of the reassembly buffer.  This will spin through
	 * the buffer and call File::DeliverStream() and File::Gap() wherever
	 * appropriate.
	 * @return the number of new bytes now detected as gaps in the file.
	 */
	uint64 Flush();

	/**
	 * Discards all contents of the reassembly buffer up to a given sequence
	 * number.  This will spin through the buffer and call
	 * File::DeliverStream() and File::Gap() wherever appropriate.
	 * @param sequence the sequence number to flush until.
	 * @return the number of new bytes now detected as gaps in the file.
	 */
	uint64 FlushTo(uint64 sequence);

	/**
	 * @return whether the reassembler is currently is the process of flushing
	 * out the contents of its buffer.
	 */
	bool IsCurrentlyFlushing() const
		{ return flushing; }

protected:
	FileReassembler();

	DECLARE_SERIAL(FileReassembler);

	void Undelivered(uint64 up_to_seq);
	void BlockInserted(DataBlock* b);
	void Overlap(const u_char* b1, const u_char* b2, uint64 n);

	File* the_file;
	bool flushing;
};

} // namespace analyzer::* 

#endif
