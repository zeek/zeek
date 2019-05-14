// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>
#include <vector>

#include "zeek-config.h"

#include "Reassem.h"
#include "Serializer.h"

static const bool DEBUG_reassem = false;

DataBlock::DataBlock(Reassembler* reass, const u_char* data,
                     uint64 size, uint64 arg_seq, DataBlock* arg_prev,
                     DataBlock* arg_next, ReassemblerType reassem_type)
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

	reassembler = reass;
	reassembler->size_of_all_blocks += size;

	rtype = reassem_type;
	Reassembler::sizes[rtype] += pad_size(size) + padded_sizeof(DataBlock);
	Reassembler::total_size += pad_size(size) + padded_sizeof(DataBlock);
	}

uint64 Reassembler::total_size = 0;
uint64 Reassembler::sizes[REASSEM_NUM];

Reassembler::Reassembler(uint64 init_seq, ReassemblerType reassem_type)
	:  blocks(), last_block(), old_blocks(), last_old_block(),
	  last_reassem_seq(init_seq), trim_seq(init_seq),
	  max_old_blocks(0), total_old_blocks(0), size_of_all_blocks(0),
	  rtype(reassem_type)
	{
	}

Reassembler::~Reassembler()
	{
	ClearBlocks();
	ClearOldBlocks();
	}

void Reassembler::CheckOverlap(DataBlock *head, DataBlock *tail,
					uint64 seq, uint64 len, const u_char* data)
	{
	if ( ! head || ! tail )
		return;

	if ( seq == tail->upper )
		// Special case check for common case of appending to the end.
		return;

	uint64 upper = (seq + len);

	for ( DataBlock* b = head; b; b = b->next )
		{
		uint64 nseq = seq;
		uint64 nupper = upper;
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

		uint64 overlap_offset = (nseq - b->seq);
		uint64 overlap_len = (nupper - nseq);

		if ( overlap_len )
			Overlap(&b->block[overlap_offset], ndata, overlap_len);
		}
	}

void Reassembler::NewBlock(double t, uint64 seq, uint64 len, const u_char* data)
	{
	if ( len == 0 )
		return;

	uint64 upper_seq = seq + len;

	CheckOverlap(old_blocks, last_old_block, seq, len, data);

	if ( upper_seq <= trim_seq )
		// Old data, don't do any work for it.
		return;

	CheckOverlap(blocks, last_block, seq, len, data);

	if ( seq < trim_seq )
		{ // Partially old data, just keep the good stuff.
		uint64 amount_old = trim_seq - seq;

		data += amount_old;
		seq += amount_old;
		len -= amount_old;
		}

	DataBlock* start_block;

	if ( ! blocks )
		blocks = last_block = start_block =
			new DataBlock(this, data, len, seq, 0, 0, rtype);
	else
		start_block = AddAndCheck(blocks, seq, upper_seq, data);

	BlockInserted(start_block);
	}

uint64 Reassembler::TrimToSeq(uint64 seq)
	{
	uint64 num_missing = 0;

	// Do this accounting before looking for Undelivered data,
	// since that will alter last_reassem_seq.

	if ( blocks )
		{
		if ( blocks->seq > last_reassem_seq )
			// An initial hole.
			num_missing += blocks->seq - last_reassem_seq;
		}

	else if ( seq > last_reassem_seq )
		{ // Trimming data we never delivered.
		if ( ! blocks )
			// We won't have any accounting based on blocks
			// for this hole.
			num_missing += seq - last_reassem_seq;
		}

	if ( seq > last_reassem_seq )
		{
		// We're trimming data we never delivered.
		Undelivered(seq);
		}

	while ( blocks && blocks->upper <= seq )
		{
		DataBlock* b = blocks->next;

		if ( b && b->seq <= seq )
			{
			if ( blocks->upper != b->seq )
				num_missing += b->seq - blocks->upper;
			}
		else
			{
			// No more blocks - did this one make it to seq?
			// Second half of test is for acks of FINs, which
			// don't get entered into the sequence space.
			if ( blocks->upper != seq && blocks->upper != seq - 1 )
				num_missing += seq - blocks->upper;
			}

		if ( max_old_blocks )
			{
			// Move block over to old_blocks queue.
			blocks->next = 0;

			if ( last_old_block )
				{
				blocks->prev = last_old_block;
				last_old_block->next = blocks;
				}
			else
				{
				blocks->prev = 0;
				old_blocks = blocks;
				}

			last_old_block = blocks;
			total_old_blocks++;

			while ( old_blocks && total_old_blocks > max_old_blocks )
				{
				DataBlock* next = old_blocks->next;
				delete old_blocks;
				old_blocks = next;
				total_old_blocks--;
				}
			}

		else
			delete blocks;

		blocks = b;
		}

	if ( blocks )
		{
		blocks->prev = 0;

		// If we skipped over some undeliverable data, then
		// it's possible that this block is now deliverable.
		// Give it a try.
		if ( blocks->seq == last_reassem_seq )
			BlockInserted(blocks);
		}
	else
		last_block = 0;

	if ( seq > trim_seq )
		// seq is further ahead in the sequence space.
		trim_seq = seq;

	return num_missing;
	}

void Reassembler::ClearBlocks()
	{
	while ( blocks )
		{
		DataBlock* b = blocks->next;
		delete blocks;
		blocks = b;
		}

	last_block = 0;
	}

void Reassembler::ClearOldBlocks()
	{
	while ( old_blocks )
		{
		DataBlock* b = old_blocks->next;
		delete old_blocks;
		old_blocks = b;
		}

	last_old_block = 0;
	}

uint64 Reassembler::TotalSize() const
	{
	return size_of_all_blocks;
	}

void Reassembler::Describe(ODesc* d) const
	{
	d->Add("reassembler");
	}

void Reassembler::Undelivered(uint64 up_to_seq)
	{
	// TrimToSeq() expects this.
	last_reassem_seq = up_to_seq;
	}

DataBlock* Reassembler::AddAndCheck(DataBlock* b, uint64 seq, uint64 upper,
					const u_char* data)
	{
	if ( DEBUG_reassem )
		{
		DEBUG_MSG("%.6f Reassembler::AddAndCheck seq=%" PRIu64", upper=%" PRIu64"\n",
		          network_time, seq, upper);
		}

	// Special check for the common case of appending to the end.
	if ( last_block && seq == last_block->upper )
		{
		last_block = new DataBlock(this, data, upper - seq,
		                           seq, last_block, 0, rtype);
		return last_block;
		}

	// Find the first block that doesn't come completely before the
	// new data.
	while ( b->next && b->upper <= seq )
		b = b->next;

	if ( b->upper <= seq )
		{
		// b is the last block, and it comes completely before
		// the new block.
		last_block = new DataBlock(this, data, upper - seq,
		                           seq, b, 0, rtype);
		return last_block;
		}

	DataBlock* new_b = 0;

	if ( upper <= b->seq )
		{
		// The new block comes completely before b.
		new_b = new DataBlock(this, data, upper - seq, seq,
		                      b->prev, b, rtype);
		if ( b == blocks )
			blocks = new_b;
		return new_b;
		}

	// The blocks overlap.
	if ( seq < b->seq )
		{
		// The new block has a prefix that comes before b.
		uint64 prefix_len = b->seq - seq;
		new_b = new DataBlock(this, data, prefix_len, seq,
		                      b->prev, b, rtype);
		if ( b == blocks )
			blocks = new_b;

		data += prefix_len;
		seq += prefix_len;
		}
	else
		new_b = b;

	uint64 overlap_start = seq;
	uint64 overlap_offset = overlap_start - b->seq;
	uint64 new_b_len = upper - seq;
	uint64 b_len = b->upper - overlap_start;
	uint64 overlap_len = min(new_b_len, b_len);

	if ( overlap_len < new_b_len )
		{
		// Recurse to resolve remainder of the new data.
		data += overlap_len;
		seq += overlap_len;

		if ( new_b == b )
			new_b = AddAndCheck(b, seq, upper, data);
		else
			(void) AddAndCheck(b, seq, upper, data);
		}

	if ( new_b->prev == last_block )
		last_block = new_b;

	return new_b;
	}

uint64 Reassembler::MemoryAllocation(ReassemblerType rtype)
	{
	return Reassembler::sizes[rtype];
	}

bool Reassembler::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

Reassembler* Reassembler::Unserialize(UnserialInfo* info)
	{
	return (Reassembler*) SerialObj::Unserialize(info, SER_REASSEMBLER);
	}

bool Reassembler::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_REASSEMBLER, BroObj);

	// I'm not sure if it makes sense to actually save the buffered data.
	// For now, we just remember the seq numbers so that we don't get
	// complaints about missing content.
	return SERIALIZE(trim_seq) && SERIALIZE(int(0));
	}

bool Reassembler::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BroObj);

	blocks = last_block = 0;

	int dummy; // For backwards compatibility.
	if ( ! UNSERIALIZE(&trim_seq) || ! UNSERIALIZE(&dummy) )
		return false;

	last_reassem_seq = trim_seq;

	return  true;
	}
