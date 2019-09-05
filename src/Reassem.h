// See the file "COPYING" in the main distribution directory for copyright.

#ifndef reassem_h
#define reassem_h

#include "Obj.h"
#include "IPAddr.h"

// Whenever subclassing the Reassembler class
// you should add to this for known subclasses.
enum ReassemblerType {
	REASSEM_UNKNOWN,
	REASSEM_TCP,
	REASSEM_FRAG,
	REASSEM_FILE,

	// Terminal value. Add new above.
	REASSEM_NUM,
};

class Reassembler;

class DataBlock {
public:
	DataBlock(Reassembler* reass, const u_char* data,
	          uint64_t size, uint64_t seq,
	          DataBlock* prev, DataBlock* next);

	~DataBlock();

	uint64_t Size() const	{ return upper - seq; }

	DataBlock* next;	// next block with higher seq #
	DataBlock* prev;	// previous block with lower seq #
	uint64_t seq, upper;
	u_char* block;

	Reassembler* reassembler; // Non-owning pointer back to parent.
};

class Reassembler : public BroObj {
public:
	Reassembler(uint64_t init_seq, ReassemblerType reassem_type = REASSEM_UNKNOWN);
	~Reassembler() override;

	void NewBlock(double t, uint64_t seq, uint64_t len, const u_char* data);

	// Throws away all blocks up to seq.  Returns number of bytes
	// if not all in-sequence, 0 if they were.
	uint64_t TrimToSeq(uint64_t seq);

	// Delete all held blocks.
	void ClearBlocks();
	void ClearOldBlocks();

	int HasBlocks() const		{ return blocks != 0; }
	uint64_t LastReassemSeq() const	{ return last_reassem_seq; }

	uint64_t TotalSize() const;	// number of bytes buffered up

	void Describe(ODesc* d) const override;

	// Sum over all data buffered in some reassembler.
	static uint64_t TotalMemoryAllocation()	{ return total_size; }

	// Data buffered by type of reassembler.
	static uint64_t MemoryAllocation(ReassemblerType rtype);

	void SetMaxOldBlocks(uint32_t count)	{ max_old_blocks = count; }

protected:
	Reassembler()	{ }

	friend class DataBlock;

	virtual void Undelivered(uint64_t up_to_seq);

	virtual void BlockInserted(DataBlock* b) = 0;
	virtual void Overlap(const u_char* b1, const u_char* b2, uint64_t n) = 0;

	DataBlock* AddAndCheck(DataBlock* b, uint64_t seq,
				uint64_t upper, const u_char* data);

	void CheckOverlap(DataBlock *head, DataBlock *tail,
				uint64_t seq, uint64_t len, const u_char* data);

	DataBlock* blocks;
	DataBlock* last_block;

	DataBlock* old_blocks;
	DataBlock* last_old_block;

	uint64_t last_reassem_seq;
	uint64_t trim_seq;	// how far we've trimmed
	uint32_t max_old_blocks;
	uint32_t total_old_blocks;
	uint64_t size_of_all_blocks;

	ReassemblerType rtype;

	static uint64_t total_size;
	static uint64_t sizes[REASSEM_NUM];
};

inline DataBlock::~DataBlock()
	{
	reassembler->size_of_all_blocks -= Size();
	Reassembler::total_size -= pad_size(upper - seq) + padded_sizeof(DataBlock);
	Reassembler::sizes[reassembler->rtype] -= pad_size(upper - seq) + padded_sizeof(DataBlock);
	delete [] block;
	}

#endif
