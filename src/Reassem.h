// See the file "COPYING" in the main distribution directory for copyright.

#ifndef reassem_h
#define reassem_h

#include "Obj.h"
#include "IPAddr.h"

class DataBlock {
public:
	DataBlock(const u_char* data, uint64 size, uint64 seq,
			DataBlock* prev, DataBlock* next);

	~DataBlock();

	uint64 Size() const	{ return upper - seq; }

	DataBlock* next;	// next block with higher seq #
	DataBlock* prev;	// previous block with lower seq #
	uint64 seq, upper;
	u_char* block;
};



class Reassembler : public BroObj {
public:
	Reassembler(uint64 init_seq);
	virtual ~Reassembler();

	void NewBlock(double t, uint64 seq, uint64 len, const u_char* data);

	// Throws away all blocks up to seq.  Returns number of bytes
	// if not all in-sequence, 0 if they were.
	uint64 TrimToSeq(uint64 seq);

	// Delete all held blocks.
	void ClearBlocks();
	void ClearOldBlocks();

	int HasBlocks() const		{ return blocks != 0; }
	uint64 LastReassemSeq() const	{ return last_reassem_seq; }

	uint64 TotalSize() const;	// number of bytes buffered up

	void Describe(ODesc* d) const;

	bool Serialize(SerialInfo* info) const;
	static Reassembler* Unserialize(UnserialInfo* info);

	// Sum over all data buffered in some reassembler.
	static uint64 TotalMemoryAllocation()	{ return total_size; }

	void SetMaxOldBlocks(uint32 count)	{ max_old_blocks = count; }

protected:
	Reassembler()	{ }

	DECLARE_ABSTRACT_SERIAL(Reassembler);

	friend class DataBlock;

	virtual void Undelivered(uint64 up_to_seq);

	virtual void BlockInserted(DataBlock* b) = 0;
	virtual void Overlap(const u_char* b1, const u_char* b2, uint64 n) = 0;

	DataBlock* AddAndCheck(DataBlock* b, uint64 seq,
				uint64 upper, const u_char* data);

	void CheckOverlap(DataBlock *head, DataBlock *tail,
				uint64 seq, uint64 len, const u_char* data);

	DataBlock* blocks;
	DataBlock* last_block;

	DataBlock* old_blocks;
	DataBlock* last_old_block;

	uint64 last_reassem_seq;
	uint64 trim_seq;	// how far we've trimmed
	uint32 max_old_blocks;
	uint32 total_old_blocks;

	static uint64 total_size;
};

inline DataBlock::~DataBlock()
	{
	Reassembler::total_size -= pad_size(upper - seq) + padded_sizeof(DataBlock);
	delete [] block;
	}

#endif
