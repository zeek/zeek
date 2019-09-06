// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>
#include <vector>

#include "zeek-config.h"

#include "Reassem.h"

uint64_t Reassembler::total_size = 0;
uint64_t Reassembler::sizes[REASSEM_NUM];

DataBlock::DataBlock(Reassembler* reass, const u_char* data,
                     uint64_t size, uint64_t arg_seq, DataBlock* arg_prev,
                     DataBlock* arg_next)
	{
	seq = arg_seq;
	upper = seq + size;
	block = new u_char[size];

	memcpy((void*) block, (const void*) data, size);

	prev = arg_prev;
	next = arg_next;

	if ( prev )
		prev->next = this;
	if ( next )
		next->prev = this;

	// TODO: could probably store this pointer and do book-keeping in
	// DataBlockList instead
	reassembler = reass;
	reassembler->size_of_all_blocks += size;

	Reassembler::sizes[reass->rtype] += pad_size(size) + padded_sizeof(DataBlock);
	Reassembler::total_size += pad_size(size) + padded_sizeof(DataBlock);
	}

void DataBlockList::Size(uint64_t seq_cutoff, uint64_t* below, uint64_t* above) const
	{
	// TODO: just have book-keeping to track this info and avoid iterating ?
	for ( auto b = head; b; b = b->next )
		{
		if ( b->seq <= seq_cutoff )
			*above += b->Size();
		else
			*below += b->Size();
		}
	}

void DataBlockList::Clear()
	{
	while ( head )
		{
		auto next = head->next;
		delete head;
		head = next;
		}
	}

void DataBlockList::Add(DataBlock* block, uint64_t limit)
	{
	++total_blocks;
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
		delete head;
		head = next;
		--total_blocks;
		}
	}

DataBlock* DataBlockList::Insert(uint64_t seq, uint64_t upper,
                                 const u_char* data, Reassembler* reass,
                                 DataBlock* start)
    {
	// TODO: can probably do a lot better at finding the right insertion location

	// Empty list.
	if ( ! head )
		{
		head = tail = new DataBlock(reass, data, upper - seq, seq, 0, 0);
		++total_blocks;
		return head;
		}

	// Special check for the common case of appending to the end.
	if ( tail && seq == tail->upper )
		{
		tail = new DataBlock(reass, data, upper - seq, seq, tail, 0);
		++total_blocks;
		return tail;
		}

	auto b = start ? start : head;

	// Find the first block that doesn't come completely before the
	// new data.
	while ( b->next && b->upper <= seq )
		b = b->next;

	if ( b->upper <= seq )
		{
		// b is the last block, and it comes completely before
		// the new block.
		tail = new DataBlock(reass, data, upper - seq, seq, b, 0);
		++total_blocks;
		return tail;
		}

	DataBlock* new_b = 0;

	if ( upper <= b->seq )
		{
		// The new block comes completely before b.
		new_b = new DataBlock(reass, data, upper - seq, seq, b->prev, b);
		++total_blocks;

		if ( b == head )
			head = new_b;

		return new_b;
		}

	// The blocks overlap.
	if ( seq < b->seq )
		{
		// The new block has a prefix that comes before b.
		uint64_t prefix_len = b->seq - seq;
		new_b = new DataBlock(reass, data, prefix_len, seq, b->prev, b);
		++total_blocks;

		if ( b == head )
			head = new_b;

		data += prefix_len;
		seq += prefix_len;
		}
	else
		new_b = b;

	uint64_t overlap_start = seq;
	uint64_t overlap_offset = overlap_start - b->seq;
	uint64_t new_b_len = upper - seq;
	uint64_t b_len = b->upper - overlap_start;
	uint64_t overlap_len = min(new_b_len, b_len);

	if ( overlap_len < new_b_len )
		{
		// Recurse to resolve remainder of the new data.
		data += overlap_len;
		seq += overlap_len;

		if ( new_b == b )
			new_b = Insert(seq, upper, data, reass, b);
		else
			Insert(seq, upper, data, reass, b);
		}

	if ( new_b->prev == tail )
		tail = new_b;

	return new_b;
    }

uint64_t DataBlockList::Trim(uint64_t seq, Reassembler* reass,
                             uint64_t max_old, DataBlockList* old_list)
	{
	uint64_t num_missing = 0;

	// Do this accounting before looking for Undelivered data,
	// since that will alter last_reassem_seq.

	if ( head )
		{
		if ( head->seq > reass->LastReassemSeq() )
			// An initial hole.
			num_missing += head->seq - reass->LastReassemSeq();
		}

	else if ( seq > reass->LastReassemSeq() )
		{ // Trimming data we never delivered.
		if ( ! head )
			// We won't have any accounting based on blocks
			// for this hole.
			num_missing += seq - reass->LastReassemSeq();
		}

	if ( seq > reass->LastReassemSeq() )
		{
		// We're trimming data we never delivered.
		reass->Undelivered(seq);
		}

	// TODO: better loop ?

	while ( head && head->upper <= seq )
		{
		DataBlock* b = head->next;

		if ( b && b->seq <= seq )
			{
			if ( head->upper != b->seq )
				num_missing += b->seq - head->upper;
			}
		else
			{
			// No more blocks - did this one make it to seq?
			// Second half of test is for acks of FINs, which
			// don't get entered into the sequence space.
			if ( head->upper != seq && head->upper != seq - 1 )
				num_missing += seq - head->upper;
			}

		if ( max_old )
			old_list->Add(head, max_old);
		else
			delete head;

		head = b;
		}

	if ( head )
		{
		head->prev = 0;

		// If we skipped over some undeliverable data, then
		// it's possible that this block is now deliverable.
		// Give it a try.
		if ( head->seq == reass->LastReassemSeq() )
			reass->BlockInserted(head);
		}
	else
		tail = 0;

	reass->SetTrimSeq(seq);
	return num_missing;
	}

Reassembler::Reassembler(uint64_t init_seq, ReassemblerType reassem_type)
	: last_reassem_seq(init_seq), trim_seq(init_seq),
	  max_old_blocks(0), size_of_all_blocks(0),
	  rtype(reassem_type)
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

	if ( seq == tail->upper )
		// Special case check for common case of appending to the end.
		return;

	uint64_t upper = (seq + len);

	for ( auto b = head; b; b = b->next )
		{
		uint64_t nseq = seq;
		uint64_t nupper = upper;
		const u_char* ndata = data;

		if ( nupper <= b->seq )
			continue;

		if ( nseq >= b->upper )
			continue;

		if ( nseq < b->seq )
			{
			ndata += (b->seq - seq);
			nseq = b->seq;
			}

		if ( nupper > b->upper )
			nupper = b->upper;

		uint64_t overlap_offset = (nseq - b->seq);
		uint64_t overlap_len = (nupper - nseq);

		if ( overlap_len )
			Overlap(&b->block[overlap_offset], ndata, overlap_len);
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

	auto start_block = block_list.Insert(seq, upper_seq, data, this);;
	BlockInserted(start_block);
	}

uint64_t Reassembler::TrimToSeq(uint64_t seq)
	{
	return block_list.Trim(seq, this, max_old_blocks, &old_block_list);
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
	return size_of_all_blocks;
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

