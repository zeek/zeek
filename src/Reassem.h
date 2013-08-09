// See the file "COPYING" in the main distribution directory for copyright.

#ifndef reassem_h
#define reassem_h

#include "Obj.h"
#include "IPAddr.h"

class DataBlock {
public:
	DataBlock(const u_char* data, int size, int seq,
			DataBlock* prev, DataBlock* next);

	~DataBlock();

	int Size() const	{ return upper - seq; }

	DataBlock* next;	// next block with higher seq #
	DataBlock* prev;	// previous block with lower seq #
	int seq, upper;
	u_char* block;
};


enum ReassemblerType { REASSEM_IP, REASSEM_TCP };

class Reassembler : public BroObj {
public:
	Reassembler(int init_seq, ReassemblerType arg_type);
	virtual ~Reassembler();

	void NewBlock(double t, int seq, int len, const u_char* data);

	// Throws away all blocks up to seq.  Returns number of bytes
	// if not all in-sequence, 0 if they were.
	int TrimToSeq(int seq);

	// Delete all held blocks.
	void ClearBlocks();

	int HasBlocks() const		{ return blocks != 0; }
	int LastReassemSeq() const	{ return last_reassem_seq; }

	int TotalSize() const;	// number of bytes buffered up

	void Describe(ODesc* d) const;

	bool Serialize(SerialInfo* info) const;
	static Reassembler* Unserialize(UnserialInfo* info);

	// Sum over all data buffered in some reassembler.
	static unsigned int TotalMemoryAllocation()	{ return total_size; }

protected:
	Reassembler()	{ }

	DECLARE_ABSTRACT_SERIAL(Reassembler);

	friend class DataBlock;

	virtual void Undelivered(int up_to_seq);

	virtual void BlockInserted(DataBlock* b) = 0;
	virtual void Overlap(const u_char* b1, const u_char* b2, int n) = 0;

	DataBlock* AddAndCheck(DataBlock* b, int seq,
				int upper, const u_char* data);

	DataBlock* blocks;
	DataBlock* last_block;
	int last_reassem_seq;
	int trim_seq;	// how far we've trimmed

	static unsigned int total_size;
};

inline DataBlock::~DataBlock()
	{
	Reassembler::total_size -= pad_size(upper - seq) + padded_sizeof(DataBlock);
	delete [] block;
	}

#endif
