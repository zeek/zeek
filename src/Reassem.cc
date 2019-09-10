// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>
#include <vector>

#include "zeek-config.h"

#include "Reassem.h"

uint64_t Reassembler::total_size = 0;
uint64_t Reassembler::sizes[REASSEM_NUM];

DataBlock::DataBlock(DataBlockList* list, const u_char* data,
                     uint64_t size, uint64_t arg_seq)
	{
	seq = arg_seq;
	upper = seq + size;
	block = new u_char[size];

	memcpy((void*) block, (const void*) data, size);

	++list->total_blocks;
	list->total_data_size += size;

	Reassembler::sizes[list->reassembler->rtype] += pad_size(size);
	Reassembler::total_size += pad_size(size);
	}

DataBlockNode::DataBlockNode(DataBlockList* list, const u_char* data,
                             uint64_t size, uint64_t arg_seq,
                             DataBlockNode* arg_prev, DataBlockNode* arg_next)
	: DataBlockNode(new DataBlock(list, data, size, arg_seq),
	                arg_prev, arg_next)
	{
	}

DataBlockNode::DataBlockNode(DataBlock* arg_db,
                             DataBlockNode* arg_prev, DataBlockNode* arg_next)
    {
	prev = arg_prev;
	next = arg_next;

	if ( prev )
		prev->next = this;
	if ( next )
		next->prev = this;

	db = arg_db;
    }

bool DataBlockNode::operator<(const DataBlockNode& other) const
	{
	// TODO: maybe don't need the null-checks ?
	if ( ! db )
		return true;

	if ( other.db )
		return *db < *other.db;

	return false;
	}

void DataBlockList::DataSize(uint64_t seq_cutoff, uint64_t* below, uint64_t* above) const
	{
	// TODO: just have book-keeping to track this info and avoid iterating ?
	for ( auto b = head; b; b = b->next )
		{
		if ( b->db->seq <= seq_cutoff )
			*above += b->Size();
		else
			*below += b->Size();
		}
	}

void DataBlockList::Delete(DataBlockNode* b)
	{
	auto size = b->Size();

	--total_blocks;
	total_data_size -= size;

	Reassembler::total_size -= pad_size(size);
	Reassembler::sizes[reassembler->rtype] -= pad_size(size);

	delete b->db;
	delete b;
	}

void DataBlockList::Clear()
	{
	while ( head )
		{
		auto next = head->next;
		Delete(head);
		head = next;
		}

	tail = nullptr;
	}

void DataBlockList::Append(DataBlockNode* block, uint64_t limit)
	{
	++total_blocks;
	total_data_size += block->Size();
	block->next = nullptr;

	if ( tail )
		{
		block->prev = tail;
		tail->next = block;
		}
	else
		{
		block->prev = nullptr;
		head = tail = block;
		}

	while ( head && total_blocks > limit )
		{
		auto next = head->next;
		Delete(head);
		head = next;
		}
	}

DataBlockNode* DataBlockList::Insert(uint64_t seq, uint64_t upper,
                                     const u_char* data,
                                     DataBlockNode* start)
	{
	// TODO: can probably do a lot better at finding the right insertion location

	// Empty list.
	if ( ! head )
		{
		head = tail = new DataBlockNode(this, data, upper - seq, seq, 0, 0);
		return head;
		}

	// Special check for the common case of appending to the end.
	if ( tail && seq == tail->db->upper )
		{
		tail = new DataBlockNode(this, data, upper - seq, seq, tail, 0);
		return tail;
		}

	auto b = start ? start : head;

	// Find the first block that doesn't come completely before the
	// new data.
	while ( b->next && b->db->upper <= seq )
		b = b->next;

	if ( b->db->upper <= seq )
		{
		// b is the last block, and it comes completely before
		// the new block.
		tail = new DataBlockNode(this, data, upper - seq, seq, b, 0);
		return tail;
		}

	DataBlockNode* new_b = 0;

	if ( upper <= b->db->seq )
		{
		// The new block comes completely before b.
		new_b = new DataBlockNode(this, data, upper - seq, seq, b->prev, b);

		if ( b == head )
			head = new_b;

		return new_b;
		}

	// The blocks overlap.
	if ( seq < b->db->seq )
		{
		// The new block has a prefix that comes before b.
		uint64_t prefix_len = b->db->seq - seq;
		new_b = new DataBlockNode(this, data, prefix_len, seq, b->prev, b);

		if ( b == head )
			head = new_b;

		data += prefix_len;
		seq += prefix_len;
		}
	else
		new_b = b;

	uint64_t overlap_start = seq;
	uint64_t overlap_offset = overlap_start - b->db->seq;
	uint64_t new_b_len = upper - seq;
	uint64_t b_len = b->db->upper - overlap_start;
	uint64_t overlap_len = min(new_b_len, b_len);

	if ( overlap_len < new_b_len )
		{
		// Recurse to resolve remainder of the new data.
		data += overlap_len;
		seq += overlap_len;

		if ( new_b == b )
			new_b = Insert(seq, upper, data, b);
		else
			Insert(seq, upper, data, b);
		}

	if ( new_b->prev == tail )
		tail = new_b;

	return new_b;
	}

uint64_t DataBlockList::Trim(uint64_t seq, uint64_t max_old,
                             DataBlockList* old_list)
	{
	uint64_t num_missing = 0;

	// Do this accounting before looking for Undelivered data,
	// since that will alter last_reassem_seq.

	if ( head )
		{
		if ( head->db->seq > reassembler->LastReassemSeq() )
			// An initial hole.
			num_missing += head->db->seq - reassembler->LastReassemSeq();
		}

	else if ( seq > reassembler->LastReassemSeq() )
		{ // Trimming data we never delivered.
		if ( ! head )
			// We won't have any accounting based on blocks
			// for this hole.
			num_missing += seq - reassembler->LastReassemSeq();
		}

	if ( seq > reassembler->LastReassemSeq() )
		{
		// We're trimming data we never delivered.
		reassembler->Undelivered(seq);
		}

	// TODO: better loop ?

	while ( head && head->db->upper <= seq )
		{
		DataBlockNode* b = head->next;

		if ( b && b->db->seq <= seq )
			{
			if ( head->db->upper != b->db->seq )
				num_missing += b->db->seq - head->db->upper;
			}
		else
			{
			// No more blocks - did this one make it to seq?
			// Second half of test is for acks of FINs, which
			// don't get entered into the sequence space.
			if ( head->db->upper != seq && head->db->upper != seq - 1 )
				num_missing += seq - head->db->upper;
			}

		if ( max_old )
			{
			--total_blocks;
			total_data_size -= head->Size();
			old_list->Append(head, max_old);
			}
		else
			Delete(head);

		head = b;
		}

	if ( head )
		{
		head->prev = 0;

		// If we skipped over some undeliverable data, then
		// it's possible that this block is now deliverable.
		// Give it a try.
		if ( head->db->seq == reassembler->LastReassemSeq() )
			reassembler->BlockInserted(head);
		}
	else
		tail = 0;

	reassembler->SetTrimSeq(seq);
	return num_missing;
	}

Reassembler::Reassembler(uint64_t init_seq, ReassemblerType reassem_type)
	: block_list(this), old_block_list(this),
	  last_reassem_seq(init_seq), trim_seq(init_seq),
	  max_old_blocks(0), rtype(reassem_type)
	{
	}

void Reassembler::CheckOverlap(const DataBlockList& list,
                               uint64_t seq, uint64_t len,
                               const u_char* data)
	{
	if ( list.Empty() )
		return;

	auto head = list.Head();
	auto tail = list.Tail();

	// TODO: better way to iterate ?

	if ( seq == tail->db->upper )
		// Special case check for common case of appending to the end.
		return;

	uint64_t upper = (seq + len);

	for ( auto b = head; b; b = b->next )
		{
		uint64_t nseq = seq;
		uint64_t nupper = upper;
		const u_char* ndata = data;

		if ( nupper <= b->db->seq )
			continue;

		if ( nseq >= b->db->upper )
			continue;

		if ( nseq < b->db->seq )
			{
			ndata += (b->db->seq - seq);
			nseq = b->db->seq;
			}

		if ( nupper > b->db->upper )
			nupper = b->db->upper;

		uint64_t overlap_offset = (nseq - b->db->seq);
		uint64_t overlap_len = (nupper - nseq);

		if ( overlap_len )
			Overlap(&b->db->block[overlap_offset], ndata, overlap_len);
		}
	}

void Reassembler::NewBlock(double t, uint64_t seq, uint64_t len, const u_char* data)
	{
	if ( len == 0 )
		return;

	uint64_t upper_seq = seq + len;

	CheckOverlap(old_block_list, seq, len, data);

	if ( upper_seq <= trim_seq )
		// Old data, don't do any work for it.
		return;

	CheckOverlap(block_list, seq, len, data);

	if ( seq < trim_seq )
		{ // Partially old data, just keep the good stuff.
		uint64_t amount_old = trim_seq - seq;

		data += amount_old;
		seq += amount_old;
		len -= amount_old;
		}

	auto start_block = block_list.Insert(seq, upper_seq, data);;
	BlockInserted(start_block);
	}

uint64_t Reassembler::TrimToSeq(uint64_t seq)
	{
	return block_list.Trim(seq, max_old_blocks, &old_block_list);
	}

void Reassembler::ClearBlocks()
	{
	block_list.Clear();
	}

void Reassembler::ClearOldBlocks()
	{
	old_block_list.Clear();
	}

uint64_t Reassembler::TotalSize() const
	{
	return block_list.DataSize() + old_block_list.DataSize();
	}

void Reassembler::Describe(ODesc* d) const
	{
	d->Add("reassembler");
	}

void Reassembler::Undelivered(uint64_t up_to_seq)
	{
	// TrimToSeq() expects this.
	last_reassem_seq = up_to_seq;
	}

uint64_t Reassembler::MemoryAllocation(ReassemblerType rtype)
	{
	return Reassembler::sizes[rtype];
	}

