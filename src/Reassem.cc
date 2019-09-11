// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>
#include <vector>

#include "zeek-config.h"

#include "util.h"
#include "Reassem.h"

uint64_t Reassembler::total_size = 0;
uint64_t Reassembler::sizes[REASSEM_NUM];

DataBlock::DataBlock(const u_char* data, uint64_t size, uint64_t arg_seq)
	: seq(arg_seq), upper(arg_seq + size), block(new u_char[size])
	{
	memcpy((void*) block, (const void*) data, size);
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

size_t DataBlockList::PickLevel()
	{
	// TODO: add options to configure this
	constexpr auto max_levels = 16u;
	constexpr auto probability = 0.5;
	constexpr auto cutoff = static_cast<uint32_t>(probability * RAND_MAX);

	auto num_levels = levels.size();
	// Creates at most a single new level.
	auto max = num_levels < max_levels ? num_levels : max_levels;

	auto rval = 0u;

	for ( ; ; )
		{
		auto flip = static_cast<uint32_t>(bro_random()) < cutoff;

		if ( ! flip )
			break;

		++rval;

		if ( rval == max )
			break;
		}

	return rval;
	}

void DataBlockList::DataSize(uint64_t seq_cutoff, uint64_t* below, uint64_t* above) const
	{
	for ( auto b = head; b; b = b->next )
		{
		if ( b->db->seq <= seq_cutoff )
			*above += b->Size();
		else
			*below += b->Size();
		}
	}

DataBlock* DataBlockList::DeleteNode(DataBlockNode* n)
	{
	auto rval = n->db;

	--total_blocks;
	total_data_size -= rval->Size();

	while ( n )
		{
		auto next = n->up;
		delete n;
		n = next;
		}

	return rval;
	}

void DataBlockList::DeleteNodeAndBlock(DataBlockNode* n)
	{
	auto db = DeleteNode(n);
	auto size = db->Size();
	delete db;
	Reassembler::total_size -= size;
	Reassembler::sizes[reassembler->rtype] -= size;
	}

void DataBlockList::Clear()
	{
	while ( head )
		{
		auto next = head->next;
		DeleteNodeAndBlock(head);
		head = next;
		}

	tail = nullptr;
	levels.clear();
	}

void DataBlockList::Resize(size_t size)
	{
	while ( total_blocks > size )
		{
		auto next = head->next;
		DeleteNodeAndBlock(head);
		head = next;
		}

	if ( head )
		{
		IncreaseHeadHeight();
		RemoveEmptySkipLevels();
		}
	else
		{
		tail = nullptr;
		levels.clear();
		}
	}

void DataBlockList::IncreaseHeadHeight()
	{
	auto up = head;
	auto next = head->next;
	auto last_below = head;

	// Adjust head up pointers so that it will be tallest node.
	for ( auto i = 0u; i < levels.size(); ++i )
		{
		if ( up )
			{
			up->prev = nullptr;
			levels[i] = up;
			last_below = up;
			next = up->next;
			up = up->up;
			}
		else
			{
			while ( next )
				{
				if ( next->up )
					{
					next = next->up;
					break;
					}

				next = next->next;
				}

			levels[i] = new DataBlockNode(head->db, nullptr, next);
			levels[i]->down = last_below;
			last_below->up = levels[i];
			last_below = levels[i];
			}
		}
	}

void DataBlockList::RemoveEmptySkipLevels()
	{
	for ( int i = levels.size() - 1; i > 0; --i )
		{
		if ( levels[i]->next )
			break;

		levels[i - 1]->up = nullptr;
		delete levels[i];
		levels.pop_back();
		}
	}

void DataBlockList::Append(DataBlock* block)
	{
	++total_blocks;
	total_data_size += block->Size();

	if ( tail )
		tail = new DataBlockNode(block, tail, nullptr);
	else
		head = tail = new DataBlockNode(block, nullptr, nullptr);

	InsertIntoSkipLists(tail);
	}

DataBlockNode* DataBlockList::FindFirstBlockAfter(uint64_t seq) const
	{
	if ( levels.empty() )
		return nullptr;

	auto b = levels[levels.size() - 1];

	for ( ; ; )
		{
		if ( b->db->upper <= seq )
			{
			if ( b->next )
				{
				if ( b->next->db->upper <= seq )
					b = b->next;
				else
					{
					if ( b->down )
						b = b->down;
					else
						{
						b = b->next;
						break;
						}
					}
				}
			else
				{
				if ( b->down )
					b = b->down;
				else
					break;
				}

			}
		else
			{
			while ( b->down )
				b = b->down;

			break;
			}
		}

	return b;
	}

void DataBlockList::InsertIntoSkipLists(DataBlockNode* nn)
	{
	auto num_levels = levels.size();
	size_t lvl;
	auto prev = nn->prev;
	auto db = nn->db;

	if ( prev )
		lvl = PickLevel();
	else
		// A new head node needs to be as tall as current tallest
		// TODO: probably should use a sentinel node for the head, or else
		// this potentially does very poorly if there's a situation where
		// we always insert many elements at the head (unlikely for our usage ?)
		lvl = num_levels ? num_levels - 1 : 0;

	auto p = prev;
	DataBlockNode* last_insert_below = nn;

	if ( levels.empty() )
		levels.emplace_back(nn);
	else
		{
		if ( ! prev )
			// New head node
			levels[0] = nn;
		}

	for ( auto i = 1u; i <= lvl; ++i )
		{
		while ( p && ! p->up )
			p = p->prev;

		if ( p )
			{
			p = p->up;
			auto n = new DataBlockNode(db, p, p->next);
			n->down = last_insert_below;
			last_insert_below->up = n;
			last_insert_below = n;
			}
		else
			{
			if ( i == levels.size() )
				{
				// New tallest node
				// Ensure head remains same height as tallest node
				auto taller_head = new DataBlockNode(levels[i - 1]->db,
					                                 nullptr, nullptr);
				taller_head->down = levels[i - 1];
				levels[i - 1]->up = taller_head;
				levels.emplace_back(taller_head);

				if ( taller_head->db == db )
					last_insert_below = taller_head;
				else
					{
					auto n = new DataBlockNode(db, taller_head, nullptr);
					n->down = last_insert_below;
					last_insert_below->up = n;
					last_insert_below = n;
					}
				}
			else
				{
				// New head node
				auto n = new DataBlockNode(db, nullptr, levels[i]);
				levels[i] = n;
				n->down = last_insert_below;
				last_insert_below->up = n;
				last_insert_below = n;
				}
			}
		}
	}

DataBlockNode* DataBlockList::Insert(uint64_t seq, uint64_t upper,
                                     const u_char* data,
                                     DataBlockNode* prev, DataBlockNode* next)
	{
	auto size = upper - seq;
	auto db = new DataBlock(data, size, seq);
	Reassembler::sizes[reassembler->rtype] += size;
	Reassembler::total_size += size;

	++total_blocks;
	total_data_size += size;
	auto rval = new DataBlockNode(db, prev, next);

	InsertIntoSkipLists(rval);

	return rval;
	}

DataBlockNode* DataBlockList::Insert(uint64_t seq, uint64_t upper,
                                     const u_char* data,
                                     DataBlockNode* start)
	{
	// Empty list.
	if ( ! head )
		{
		head = tail = Insert(seq, upper, data, 0, 0);
		return head;
		}

	// Special check for the common case of appending to the end.
	if ( tail && seq == tail->db->upper )
		{
		tail = Insert(seq, upper, data, tail, 0);
		return tail;
		}

	// Find the first block that doesn't come completely before the
	// new data.
	auto b = start;

	if ( b )
		{
		while ( b->next && b->db->upper <= seq )
			b = b->next;
		}
	else
		b = FindFirstBlockAfter(seq);

	if ( b->db->upper <= seq )
		{
		// b is the last block, and it comes completely before
		// the new block.
		tail = Insert(seq, upper, data, b, 0);
		return tail;
		}

	DataBlockNode* new_b = 0;

	if ( upper <= b->db->seq )
		{
		// The new block comes completely before b.
		new_b = Insert(seq, upper, data, b->prev, b);

		if ( b == head )
			head = new_b;

		return new_b;
		}

	// The blocks overlap.
	if ( seq < b->db->seq )
		{
		// The new block has a prefix that comes before b.
		uint64_t prefix_len = b->db->seq - seq;
		new_b = Insert(seq, seq + prefix_len, data, b->prev, b);

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
			old_list->Append(DeleteNode(head));
		else
			DeleteNodeAndBlock(head);

		head = b;
		}

	if ( max_old )
		old_list->Resize(max_old);

	if ( head )
		{
		IncreaseHeadHeight();
		RemoveEmptySkipLevels();

		// If we skipped over some undeliverable data, then
		// it's possible that this block is now deliverable.
		// Give it a try.
		if ( head->db->seq == reassembler->LastReassemSeq() )
			reassembler->BlockInserted(head);
		}
	else
		{
		tail = nullptr;
		levels.clear();
		}

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

	if ( seq == tail->db->upper )
		// Special case check for common case of appending to the end.
		return;

	uint64_t upper = (seq + len);

	for ( auto b = list.FindFirstBlockAfter(seq); b; b = b->next )
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

