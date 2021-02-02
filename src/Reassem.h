// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <assert.h>
#include <string.h>
#include <sys/types.h> // for u_char
#include <cstdint>
#include <map>

#include "zeek/Obj.h"

namespace zeek {

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

/**
 * A block/segment of data for use in the reassembly process.
 */
class DataBlock {
public:

	/**
	 * Create a data block/segment with associated sequence numbering.
	 */
	DataBlock(const u_char* data, uint64_t size, uint64_t seq);

	DataBlock(const DataBlock& other)
		{
		seq = other.seq;
		upper = other.upper;
		auto size = other.Size();
		block = new u_char[size];
		memcpy(block, other.block, size);
		}

	DataBlock(DataBlock&& other)
		{
		seq = other.seq;
		upper = other.upper;
		block = other.block;
		other.block = nullptr;
		}

	DataBlock& operator=(const DataBlock& other)
		{
		if ( this == &other )
			return *this;

		seq = other.seq;
		upper = other.upper;
		auto size = other.Size();
		delete [] block;
		block = new u_char[size];
		memcpy(block, other.block, size);
		return *this;
		}

	DataBlock& operator=(DataBlock&& other)
		{
		if ( this == &other )
			return *this;

		seq = other.seq;
		upper = other.upper;
		delete [] block;
		block = other.block;
		other.block = nullptr;
		return *this;
		}

	~DataBlock()
		{ delete [] block; }

	/**
	 * @return length of the data block
	 */
	uint64_t Size() const
		{ return upper - seq; }

	uint64_t seq;
	uint64_t upper;
	u_char* block;
};

using DataBlockMap = std::map<uint64_t, DataBlock>;


/**
 * The data structure used for reassembling arbitrary sequences of data
 * blocks/segments.  It internally uses an ordered map (std::map).
 */
class DataBlockList {
public:

	DataBlockList()
		{ }

	DataBlockList(Reassembler* r) : reassembler(r)
		{ }

	~DataBlockList()
		{ Clear(); }

	/**
	 * @return iterator to start of the block list.
	 */
	DataBlockMap::const_iterator Begin() const
		{ return block_map.begin(); }

	/**
	 * @return iterator to end of the block list (one past last element).
	 */
	DataBlockMap::const_iterator End() const
		{ return block_map.end(); }

	/**
	 * @return reference to the first data block in the list.
	 * Must not be called when the list is empty.
	 */
	const DataBlock& FirstBlock() const
		{ assert(block_map.size()); return block_map.begin()->second; }

	/**
	 * @return reference to the last data block in the list.
	 * Must not be called when the list is empty.
	 */
	const DataBlock& LastBlock() const
		{ assert(block_map.size()); return block_map.rbegin()->second; }

	/**
	 * @return whether the list is empty.
	 */
	bool Empty() const
		{ return block_map.empty(); };

	/**
	 * @return the number of blocks in the list.
	 */
	size_t NumBlocks() const
		{ return block_map.size(); };

	/**
	 * @return the total size, in bytes, of all blocks in the list.
	 */
	size_t DataSize() const
		{ return total_data_size; }

	/**
	 * Counts the total size of all data contained in list elements
	 * partitioned by some cutoff.
	 * WARNING: this is an O(n) operation and potentially very slow.
	 * @param seq_cutoff  the sequence number used to partition
	 * element sizes returned via "below" and "above" parameters
	 * @param below  the size in bytes of all data below "seq_cutoff"
	 * @param above  the size in bytes of all data above "seq_cutoff"
	 */
	void DataSize(uint64_t seq_cutoff, uint64_t* below, uint64_t* above) const;

	/**
	 * Remove all elements from the list
	 */
	void Clear();

	/**
	 * Insert a new data block into the list.
	 * @param seq  lower sequence number of the data block
	 * @param upper  highest sequence number of the data block
	 * @param data  points to the data block contents
	 * @param hint  a suggestion of the node from which to start searching
	 * for an insertion point or null to search from the beginning of the list
	 * @return an iterator to the element that was inserted
	 */
	DataBlockMap::const_iterator
	Insert(uint64_t seq, uint64_t upper, const u_char* data,
	       DataBlockMap::const_iterator* hint = nullptr);

	/**
	 * Insert a new data block at the end of the list and remove blocks
	 * from the beginning of the list to keep the list size under a limit.
	 * @param block  the block to append
	 * @param limit  the max number of blocks allowed (list is pruned from
	 * starting from the beginning after the insertion takes place).
	 */
	void Append(DataBlock block, uint64_t limit);


	/**
	 * Remove all elements below a given sequence number.
	 * @param seq  blocks below this number are discarded (removed/deleted)
	 * @param max_old  if non-zero instead of deleting the underlying block,
	 * move it to "old_list"
	 * @param old_list  another list to move discarded blocks into
	 * @return the amount of data (in bytes) that was not part of any
	 * discarded block (the total size of all bypassed gaps).
	 */
	uint64_t Trim(uint64_t seq, uint64_t max_old, DataBlockList* old_list);

	/**
	 * @return an iterator pointing to the first element with a segment whose
	 * starting sequence number is less than or equal to "seq".  If no such
	 * element exists, returns an iterator denoting one-past the end of the
	 * list.
	 */
	DataBlockMap::const_iterator FirstBlockAtOrBefore(uint64_t seq) const;

private:

	/**
	 * Insert a new data block into the list.
	 * @param seq  lower sequence number of the data block
	 * @param upper  highest sequence number of the data block
	 * @param data  points to the data block contents
	 * @param hint  a suggestion of the node from which to start searching
	 * for an insertion point
	 * @return an iterator to the element that was inserted
	 */
	DataBlockMap::const_iterator
	Insert(uint64_t seq, uint64_t upper, const u_char* data,
	       DataBlockMap::const_iterator hint);

	/**
	 * Removes a block from the list and updates other state which keeps
	 * track of total size of blocks.
	 * @param it  the element to remove
	 */
	void Delete(DataBlockMap::const_iterator it);

	/**
	 * Removes a block from the list and returns it, assuming it will
	 * immediately be appended to another list.
	 * @param it  the element to remove
	 * @return the removed block
	 */
	DataBlock Remove(DataBlockMap::const_iterator it);

	Reassembler* reassembler = nullptr;
	size_t total_data_size = 0;
	DataBlockMap block_map;
};

class Reassembler : public Obj {
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

	bool HasBlocks() const
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

	friend class DataBlockList;

	virtual void Undelivered(uint64_t up_to_seq);

	virtual void BlockInserted(DataBlockMap::const_iterator it) = 0;
	virtual void Overlap(const u_char* b1, const u_char* b2, uint64_t n) = 0;

	void CheckOverlap(const DataBlockList& list,
				uint64_t seq, uint64_t len, const u_char* data);

	DataBlockList block_list;
	DataBlockList old_block_list;

	uint64_t last_reassem_seq = 0;
	uint64_t trim_seq = 0;	// how far we've trimmed
	uint32_t max_old_blocks = 0;

	ReassemblerType rtype = REASSEM_UNKNOWN;

	static uint64_t total_size;
	static uint64_t sizes[REASSEM_NUM];
};

} // namespace zeek
