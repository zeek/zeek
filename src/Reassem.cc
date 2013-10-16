// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "config.h"

#include "Reassem.h"
#include "Serializer.h"

const bool DEBUG_reassem = false;

#ifdef DEBUG
int reassem_seen_bytes = 0;
int reassem_copied_bytes = 0;
#endif

DataBlock::DataBlock(const u_char* data, int size, int arg_seq,
			DataBlock* arg_prev, DataBlock* arg_next)
	{
	seq = arg_seq;
	upper = seq + size;
	block = new u_char[size];

	memcpy((void*) block, (const void*) data, size);

#ifdef DEBUG
	reassem_copied_bytes += size;
#endif

	prev = arg_prev;
	next = arg_next;

	if ( prev )
		prev->next = this;
	if ( next )
		next->prev = this;

	Reassembler::total_size += pad_size(size) + padded_sizeof(DataBlock);
	}

unsigned int Reassembler::total_size = 0;

Reassembler::Reassembler(int init_seq, ReassemblerType arg_type)
	{
	blocks = last_block = 0;
	trim_seq = last_reassem_seq = init_seq;
	}

Reassembler::~Reassembler()
	{
	ClearBlocks();
	}

void Reassembler::NewBlock(double t, int seq, int len, const u_char* data)
	{
	if ( len == 0 )
		return;

#ifdef DEBUG
	reassem_seen_bytes += len;
#endif

	int upper_seq = seq + len;

	if ( seq_delta(upper_seq, trim_seq) <= 0 )
		// Old data, don't do any work for it.
		return;

	if ( seq_delta(seq, trim_seq) < 0 )
		{ // Partially old data, just keep the good stuff.
		int amount_old = seq_delta(trim_seq, seq);

		data += amount_old;
		seq += amount_old;
		len -= amount_old;
		}

	DataBlock* start_block;

	if ( ! blocks )
		blocks = last_block = start_block =
			new DataBlock(data, len, seq, 0, 0);
	else
		start_block = AddAndCheck(blocks, seq, upper_seq, data);

	BlockInserted(start_block);
	}

int Reassembler::TrimToSeq(int seq)
	{
	int num_missing = 0;

	// Do this accounting before looking for Undelivered data,
	// since that will alter last_reassem_seq.

	if ( blocks )
		{
		if ( seq_delta(blocks->seq, last_reassem_seq) > 0 )
			// An initial hole.
			num_missing += seq_delta(blocks->seq, last_reassem_seq);
		}

	else if ( seq_delta(seq, last_reassem_seq) > 0 )
		{ // Trimming data we never delivered.
		if ( ! blocks )
			// We won't have any accounting based on blocks
			// for this hole.
			num_missing += seq_delta(seq, last_reassem_seq);
		}

	if ( seq_delta(seq, last_reassem_seq) > 0 )
		{
		// We're trimming data we never delivered.
		Undelivered(seq);
		}

	while ( blocks && seq_delta(blocks->upper, seq) <= 0 )
		{
		DataBlock* b = blocks->next;

		if ( b && seq_delta(b->seq, seq) <= 0 )
			{
			if ( blocks->upper != b->seq )
				num_missing += seq_delta(b->seq, blocks->upper);
			}
		else
			{
			// No more blocks - did this one make it to seq?
			// Second half of test is for acks of FINs, which
			// don't get entered into the sequence space.
			if ( blocks->upper != seq && blocks->upper != seq - 1 )
				num_missing += seq_delta(seq, blocks->upper);
			}

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

	if ( seq_delta(seq, trim_seq) > 0 )
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

int Reassembler::TotalSize() const
	{
	int size = 0;

	for ( DataBlock* b = blocks; b; b = b->next )
		size += b->Size();

	return size;
	}

void Reassembler::Describe(ODesc* d) const
	{
	d->Add("reassembler");
	}

void Reassembler::Undelivered(int up_to_seq)
	{
	// TrimToSeq() expects this.
	last_reassem_seq = up_to_seq;
	}

DataBlock* Reassembler::AddAndCheck(DataBlock* b, int seq, int upper,
					const u_char* data)
	{
	if ( DEBUG_reassem )
		{
		DEBUG_MSG("%.6f Reassembler::AddAndCheck seq=%d, upper=%d\n",
		          network_time, seq, upper);
		}

	// Special check for the common case of appending to the end.
	if ( last_block && seq == last_block->upper )
		{
		last_block = new DataBlock(data, upper - seq, seq,
						last_block, 0);
		return last_block;
		}

	// Find the first block that doesn't come completely before the
	// new data.
	while ( b->next && seq_delta(b->upper, seq) <= 0 )
		b = b->next;

	if ( seq_delta(b->upper, seq) <= 0 )
		{
		// b is the last block, and it comes completely before
		// the new block.
		last_block = new DataBlock(data, upper - seq, seq, b, 0);
		return last_block;
		}

	DataBlock* new_b = 0;

	if ( seq_delta(upper, b->seq) <= 0 )
		{
		// The new block comes completely before b.
		new_b = new DataBlock(data, seq_delta(upper, seq), seq,
					b->prev, b);
		if ( b == blocks )
			blocks = new_b;
		return new_b;
		}

	// The blocks overlap, complain.
	if ( seq_delta(seq, b->seq) < 0 )
		{
		// The new block has a prefix that comes before b.
		int prefix_len = seq_delta(b->seq, seq);
		new_b = new DataBlock(data, prefix_len, seq, b->prev, b);
		if ( b == blocks )
			blocks = new_b;

		data += prefix_len;
		seq += prefix_len;
		}
	else
		new_b = b;

	int overlap_start = seq;
	int overlap_offset = seq_delta(overlap_start, b->seq);
	int new_b_len = seq_delta(upper, seq);
	int b_len = seq_delta(b->upper, overlap_start);
	int overlap_len = min(new_b_len, b_len);

	Overlap(&b->block[overlap_offset], data, overlap_len);

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
