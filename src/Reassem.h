// See the file "COPYING" in the main distribution directory for copyright.

#ifndef reassem_h
#define reassem_h

#include <vector>

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

/**
 * A block/segment of data for use in the reassembly process.
 */
class DataBlock {
public:
	/**
	 * Create a data block/segment with associated sequence numbering.
	 */
	DataBlock(const u_char* data, uint64_t size, uint64_t seq);

	~DataBlock()
		{ delete [] block; }

	uint64_t Size() const
		{ return upper - seq; }

	uint64_t seq = 0;
	uint64_t upper = 0;
	u_char* block = nullptr;
};

/**
 * A node containing a block of data for us in the reassembly process data
 * structures.
 */
class DataBlockNode {
public:
	/**
	 * Creates a node and insert it into a doubly-linked list.
	 * @param db the data block associated with the node.  Ownership
	 * of the block is claimed onnly by the node in the lowest skip-list.
	 * @param prev node in doubly-linked list before this new one.
	 * @param next node in doubly-linked list after this new one.
	 */
	DataBlockNode(DataBlock* db, DataBlockNode* prev, DataBlockNode* next);

	/**
	 * @return size of the data block associated with this node.
	 */
	uint64_t Size() const
		{ return db->upper - db->seq; }

	DataBlockNode* next = nullptr;  // next block with higher seq #
	DataBlockNode* prev = nullptr;  // prev block with lower seq #
	DataBlockNode* down = nullptr;  // equivalent block, but lower skip-list
	DataBlockNode* up = nullptr;    // equivalent block, but higher skip-list
	DataBlock* db = nullptr;
};

/**
 * The data structure used for reassembling arbitrary sequences of data
 * blocks/segments.  It's implemented as a skip-list.
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
	 * @return the node at front of the lowest skip-list (null if empty).
	 */
	const DataBlockNode* Head() const
		{ return head; }

	/**
	 * @return the node at end of the lowest skip-list (null if empty).
	 */
	const DataBlockNode* Tail() const
		{ return tail; }

	/**
	 * @return whether there's no elements in the list.
	 */
	bool Empty() const
		{ return head == nullptr; };

	/**
	 * @return the current number of skip-list levels
	 */
	size_t SkipLevels() const
		{ return levels.size(); }

	/**
	 * @return the number of elements in the list.
	 */
	size_t NumBlocks() const
		{ return total_blocks; };

	/**
	 * @return the total size of all list elements (blocks) in bytes.
	 */
	size_t DataSize() const
		{ return total_data_size; }

	/**
	 * Counts the total size of all list elements paritioned by some
	 * cutoff.  WARNING: this is an O(n) operation and potentially very slow.
	 * @param seq_cutoff the sequence number used to partition
	 * element sizes returning in the "below" and "above" parameters
	 * @param below the size in bytes of all elements below "seq_cutoff"
	 * @param above the size in bytes of all elements above "seq_cutoff"
	 */
	void DataSize(uint64_t seq_cutoff, uint64_t* below, uint64_t* above) const;

	/**
	 * Remove all elements from the list.
	 */
	void Clear();

	/**
	 * Keep the first "size" elements and remove/delete the rest from the list.
	 */
	void Resize(size_t size);

	/**
	 * Insert a new data block/node into the list.
	 * @param seq lower sequence number of the data block
	 * @param upper highest sequence number of the data block
	 * @param data points to the data block contents
	 * @param start a suggestion of what node to start searching for the
	 * insertion point form.
	 */
	DataBlockNode* Insert(uint64_t seq, uint64_t upper, const u_char* data,
	                      DataBlockNode* start = nullptr);

	/**
	 * Insert a new data block/node into the list.
	 * @param seq lower sequence number of the data block
	 * @param upper highest sequence number of the data block
	 * @param data points to the data block contents
	 * @param prev the node in lowest-skip list that comes before the new one.
	 * May be null, indicating insertion of a new head node.
	 * @param next the node in lowest-skip list that comes after the new one.
	 * May be null indicating insertion of a new tail node.
	 */
	DataBlockNode* Insert(uint64_t seq, uint64_t upper, const u_char* data,
	                      DataBlockNode* prev, DataBlockNode* next);

	/**
	 * Insert a new data block/node into the list, at the end.
	 * Skip-list nodes will be created.
	 * @param block the block to take ownership of.
	 */
	void Append(DataBlock* block);

	/**
	 * Remove all elements below a given sequence number.
	 * @param seq blocks below this number are discarded (removed/deleted)
	 * @param max_old if non-zero instead of deleting the underlying block,
	 * move it to "old_list"
	 * @param old_list another list to move discarded blocks into
	 * @return the amount of data (in bytes) that was not part of any
	 * discarded block (the total size of all bypassed gaps).
	 */
	uint64_t Trim(uint64_t seq, uint64_t max_old, DataBlockList* old_list);

	/**
	 * @return first node with a segment that contains sequence number "seq".
	 */
	DataBlockNode* FindFirstBlockAfter(uint64_t seq) const;

private:

	/**
	 * Creates additional skip-list nodes for the given lowest-level node.
	 */
	void InsertIntoSkipLists(DataBlockNode* n);

	/**
	 * Removes/deletes a node, but not the associated data block.
	 * @return the data block associated with the removed node.
	 */
	DataBlock* DeleteNode(DataBlockNode* n);

	/**
	 * Removes/deletes a node and its associated data block.
	 */
	void DeleteNodeAndBlock(DataBlockNode* n);

	/**
	 * Increases the height of the head node in the skip-list to match
	 * the tallest node.
	 */
	void IncreaseHeadHeight();

	/**
	 * Remove any levels in the skip-list that are empty.
	 */
	void RemoveEmptySkipLevels();

	/**
	 * Pick a random level/height to use for inserting a new node in skip-list.
	 */
	size_t PickLevel();

	Reassembler* reassembler = nullptr;
	DataBlockNode* head = nullptr;
	DataBlockNode* tail = nullptr;
	size_t total_blocks = 0;
	size_t total_data_size = 0;
	std::vector<DataBlockNode*> levels;
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

	virtual void BlockInserted(const DataBlockNode* b) = 0;
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
