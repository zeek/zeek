// See the file "COPYING" in the main distribution directory for copyright.

#ifndef reassem_h
#define reassem_h

#include <map>

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
	DataBlock(const u_char* data, uint64_t size, uint64_t seq);

	~DataBlock()
		{ delete [] block; }

	uint64_t Size() const
		{ return upper - seq; }

	uint64_t seq;
	uint64_t upper;
	u_char* block;
};

using DataBlockMap = std::map<uint64_t, DataBlock*>;

// TODO: add comments
class DataBlockList {
public:

	DataBlockList()
		{ }

	DataBlockList(Reassembler* r) : reassembler(r)
		{ }

	~DataBlockList()
		{ Clear(); }

	DataBlockMap::const_iterator Begin() const
		{ return block_map.begin(); }

	DataBlockMap::const_iterator End() const
		{ return block_map.end(); }

	DataBlock* FirstBlock() const
		{ return block_map.begin()->second; }

	DataBlock* LastBlock() const
		{ return block_map.rbegin()->second; }

	bool Empty() const
		{ return block_map.empty(); };

	size_t NumBlocks() const
		{ return block_map.size(); };

	size_t DataSize() const
		{ return total_data_size; }

	void DataSize(uint64_t seq_cutoff, uint64_t* below, uint64_t* above) const;

	void Clear();

	DataBlockMap::const_iterator
	Insert(uint64_t seq, uint64_t upper, const u_char* data,
	       DataBlockMap::const_iterator* hint = nullptr);

	void Append(DataBlock* block, uint64_t limit);

	uint64_t Trim(uint64_t seq, uint64_t max_old, DataBlockList* old_list);

	DataBlockMap::const_iterator FindFirstBlockBefore(uint64_t seq) const;

private:

	DataBlockMap::const_iterator
	Insert(uint64_t seq, uint64_t upper, const u_char* data,
	       DataBlockMap::const_iterator hint);

	void Delete(DataBlockMap::const_iterator it);

	DataBlock* Remove(DataBlockMap::const_iterator it);

	Reassembler* reassembler = nullptr;
	size_t total_data_size = 0;
	DataBlockMap block_map;
};

class Reassembler : public BroObj {
public:
	Reassembler(uint64_t init_seq, ReassemblerType reassem_type = REASSEM_UNKNOWN);
	~Reassembler() override	{}

	void NewBlock(double t, uint64_t seq, uint64_t len, const u_char* data);

	// Throws away all blocks up to seq.  Returns number of bytes
	// if not all in-sequence, 0 if they were.
	uint64_t TrimToSeq(uint64_t seq);

	// Delete all held blocks.
	void ClearBlocks();
	void ClearOldBlocks();

	int HasBlocks() const
		{ return ! block_list.Empty(); }

	uint64_t LastReassemSeq() const	{ return last_reassem_seq; }

	uint64_t TrimSeq() const
		{ return trim_seq; }

	void SetTrimSeq(uint64_t seq)
		{ if ( seq > trim_seq ) trim_seq = seq; }

	uint64_t TotalSize() const;	// number of bytes buffered up

	void Describe(ODesc* d) const override;

	// Sum over all data buffered in some reassembler.
	static uint64_t TotalMemoryAllocation()	{ return total_size; }

	// Data buffered by type of reassembler.
	static uint64_t MemoryAllocation(ReassemblerType rtype);

	void SetMaxOldBlocks(uint32_t count)	{ max_old_blocks = count; }

protected:
	Reassembler()	{ }

	friend class DataBlockList;

	virtual void Undelivered(uint64_t up_to_seq);

	virtual void BlockInserted(DataBlockMap::const_iterator it) = 0;
	virtual void Overlap(const u_char* b1, const u_char* b2, uint64_t n) = 0;

	void CheckOverlap(const DataBlockList& list,
				uint64_t seq, uint64_t len, const u_char* data);

	DataBlockList block_list;
	DataBlockList old_block_list;

	uint64_t last_reassem_seq;
	uint64_t trim_seq;	// how far we've trimmed
	uint32_t max_old_blocks;

	ReassemblerType rtype;

	static uint64_t total_size;
	static uint64_t sizes[REASSEM_NUM];
};

#endif
