// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Reassem.h"

#include "zeek/zeek-config.h"

#include <algorithm>
#include <limits>

#include "zeek/Desc.h"
#include "zeek/Reporter.h"

using std::min;

namespace zeek
	{

uint64_t Reassembler::total_size = 0;
uint64_t Reassembler::sizes[REASSEM_NUM];

DataBlock::DataBlock(const u_char* data, uint64_t size, uint64_t arg_seq)
	{
	seq = arg_seq;
	upper = seq + size;
	block = new u_char[size];
	memcpy(block, data, size);
	}

void DataBlockList::DataSize(uint64_t seq_cutoff, uint64_t* below, uint64_t* above) const
	{
	for ( const auto& e : block_map )
		{
		const auto& b = e.second;

		if ( b.seq <= seq_cutoff )
			{
			if ( b.upper <= seq_cutoff )
				*below += b.Size();
			else
				{
				*below += seq_cutoff - b.seq;
				*above += b.upper - seq_cutoff;
				}
			}
		else
			*above += b.Size();
		}
	}

void DataBlockList::Delete(DataBlockMap::const_iterator it)
	{
	const auto& b = it->second;
	auto size = b.Size();

	block_map.erase(it);
	total_data_size -= size;

	Reassembler::total_size -= size + sizeof(DataBlock);
	Reassembler::sizes[reassembler->rtype] -= size + sizeof(DataBlock);
	}

DataBlock DataBlockList::Remove(DataBlockMap::const_iterator it)
	{
	auto b = std::move(it->second);
	auto size = b.Size();

	block_map.erase(it);
	total_data_size -= size;

	return b;
	}

void DataBlockList::Clear()
	{
	auto total_db_size = sizeof(DataBlock) * block_map.size();
	auto total = total_data_size + total_db_size;
	Reassembler::total_size -= total;
	Reassembler::sizes[reassembler->rtype] -= total;
	total_data_size = 0;
	block_map.clear();
	}

void DataBlockList::Append(DataBlock block, uint64_t limit)
	{
	total_data_size += block.Size();

	block_map.emplace_hint(block_map.end(), block.seq, std::move(block));

	while ( block_map.size() > limit )
		Delete(block_map.begin());
	}

DataBlockMap::const_iterator DataBlockList::FirstBlockAtOrBefore(uint64_t seq) const
	{
	// Upper sequence number doesn't matter for the search
	auto it = block_map.upper_bound(seq);

	if ( it == block_map.end() )
		return block_map.empty() ? it : std::prev(it);

	if ( it == block_map.begin() )
		return block_map.end();

	return std::prev(it);
	}

DataBlockMap::const_iterator DataBlockList::Insert(uint64_t seq, uint64_t upper, const u_char* data,
                                                   DataBlockMap::const_iterator hint)
	{
	auto size = upper - seq;
	auto rval = block_map.emplace_hint(hint, seq, DataBlock(data, size, seq));

	total_data_size += size;
	Reassembler::sizes[reassembler->rtype] += size + sizeof(DataBlock);
	Reassembler::total_size += size + sizeof(DataBlock);

	return rval;
	}

DataBlockMap::const_iterator DataBlockList::Insert(uint64_t seq, uint64_t upper, const u_char* data,
                                                   DataBlockMap::const_iterator* hint)
	{
	// Empty list.
	if ( block_map.empty() )
		return Insert(seq, upper, data, block_map.end());

	const auto& last = block_map.rbegin()->second;

	// Special check for the common case of appending to the end.
	if ( seq == last.upper )
		return Insert(seq, upper, data, block_map.end());

	// Find the first block that doesn't come completely before the new data.
	DataBlockMap::const_iterator it;

	if ( hint )
		it = *hint;
	else
		{
		it = FirstBlockAtOrBefore(seq);

		if ( it == block_map.end() )
			it = block_map.begin();
		}

	while ( std::next(it) != block_map.end() && it->second.upper <= seq )
		++it;

	const auto& b = it->second;

	if ( b.upper <= seq )
		// b is the last block, and it comes completely before the new block.
		return Insert(seq, upper, data, block_map.end());

	if ( upper <= b.seq )
		// The new block comes completely before b.
		return Insert(seq, upper, data, it);

	DataBlockMap::const_iterator rval;

	// The blocks overlap.
	if ( seq < b.seq )
		{
		// The new block has a prefix that comes before b.
		uint64_t prefix_len = b.seq - seq;

		rval = Insert(seq, seq + prefix_len, data, it);

		data += prefix_len;
		seq += prefix_len;
		}
	else
		rval = it;

	uint64_t overlap_start = seq;
	uint64_t overlap_offset = overlap_start - b.seq;
	uint64_t new_b_len = upper - seq;
	uint64_t b_len = b.upper - overlap_start;
	uint64_t overlap_len = min(new_b_len, b_len);

	if ( overlap_len < new_b_len )
		{
		// Recurse to resolve remainder of the new data.
		data += overlap_len;
		seq += overlap_len;

		auto r = Insert(seq, upper, data, &it);

		if ( rval == it )
			rval = r;
		}

	return rval;
	}

uint64_t DataBlockList::Trim(uint64_t seq, uint64_t max_old, DataBlockList* old_list)
	{
	uint64_t num_missing = 0;

	// Do this accounting before looking for Undelivered data,
	// since that will alter last_reassem_seq.

	if ( ! block_map.empty() )
		{
		const auto& first = block_map.begin()->second;

		if ( first.seq > reassembler->LastReassemSeq() )
			// An initial hole.
			num_missing += first.seq - reassembler->LastReassemSeq();
		}
	else if ( seq > reassembler->LastReassemSeq() )
		{
		// Trimming data we never delivered.
		// We won't have any accounting based on blocks for this hole.
		num_missing += seq - reassembler->LastReassemSeq();
		}

	if ( seq > reassembler->LastReassemSeq() )
		{
		// We're trimming data we never delivered.
		reassembler->Undelivered(seq);
		}

	while ( ! block_map.empty() )
		{
		auto first_it = block_map.begin();
		const auto& first = first_it->second;

		if ( first.upper > seq )
			break;

		auto next = std::next(first_it);

		if ( next != block_map.end() && next->second.seq <= seq )
			{
			if ( first.upper != next->second.seq )
				num_missing += next->second.seq - first.upper;
			}
		else
			{
			// No more blocks - did this one make it to seq?
			// Second half of test is for acks of FINs, which
			// don't get entered into the sequence space.
			if ( first.upper != seq && first.upper != seq - 1 )
				num_missing += seq - first.upper;
			}

		if ( max_old )
			old_list->Append(Remove(first_it), max_old);
		else
			Delete(first_it);
		}

	if ( ! block_map.empty() )
		{
		auto first_it = block_map.begin();
		const auto& first = first_it->second;

		// If we skipped over some undeliverable data, then
		// it's possible that this block is now deliverable.
		// Give it a try.
		if ( first.seq == reassembler->LastReassemSeq() )
			reassembler->BlockInserted(first_it);
		}

	reassembler->SetTrimSeq(seq);
	return num_missing;
	}

Reassembler::Reassembler(uint64_t init_seq, ReassemblerType reassem_type)
	: block_list(this), old_block_list(this), last_reassem_seq(init_seq), trim_seq(init_seq),
	  max_old_blocks(0), rtype(reassem_type)
	{
	}

void Reassembler::CheckOverlap(const DataBlockList& list, uint64_t seq, uint64_t len,
                               const u_char* data)
	{
	if ( list.Empty() )
		return;

	const auto& last = list.LastBlock();

	if ( seq == last.upper )
		// Special case check for common case of appending to the end.
		return;

	uint64_t upper = (seq + len);

	auto it = list.FirstBlockAtOrBefore(seq);

	if ( it == list.End() )
		it = list.Begin();

	for ( ; it != list.End(); ++it )
		{
		const auto& b = it->second;
		uint64_t nseq = seq;
		uint64_t nupper = upper;
		const u_char* ndata = data;

		if ( nupper <= b.seq )
			break;

		if ( nseq >= b.upper )
			continue;

		if ( nseq < b.seq )
			{
			ndata += (b.seq - seq);
			nseq = b.seq;
			}

		if ( nupper > b.upper )
			nupper = b.upper;

		uint64_t overlap_offset = (nseq - b.seq);
		uint64_t overlap_len = (nupper - nseq);

		if ( overlap_len )
			Overlap(&b.block[overlap_offset], ndata, overlap_len);
		}
	}

void Reassembler::NewBlock(double t, uint64_t seq, uint64_t len, const u_char* data)
	{

	// Check for overflows - this should be handled by the caller
	// and possibly reported as a weird or violation if applicable.
	if ( std::numeric_limits<uint64_t>::max() - seq < len )
		{
		zeek::reporter->InternalWarning("Reassembler::NewBlock() truncating block at seq %" PRIx64
		                                " from length %" PRIu64 " to %" PRIu64,
		                                seq, len, std::numeric_limits<uint64_t>::max() - seq);
		len = std::numeric_limits<uint64_t>::max() - seq;
		}

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

	auto it = block_list.Insert(seq, upper_seq, data);
	;
	BlockInserted(it);
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

	} // namespace zeek
