// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <string.h>

#include "Queue.h"

BaseQueue::BaseQueue(int size)
	{
	const int DEFAULT_CHUNK_SIZE = 10;

	chunk_size = DEFAULT_CHUNK_SIZE;

	head = tail = num_entries = 0;

	if ( size < 0 )
		{
		entry = new ent[1];
		max_entries = 0;
		}
	else
		{
		if ( (entry = new ent[chunk_size+1]) )
			max_entries = chunk_size;
		else
			{
			entry = new ent[1];
			max_entries = 0;
			}
		}
	}

void BaseQueue::push_front(ent a)
	{
	if ( num_entries == max_entries )
		{
		resize(max_entries+chunk_size);	// make more room
		chunk_size *= 2;
		}

	++num_entries;
	if ( head )
		entry[--head] = a;
	else
		{
		head = max_entries;
		entry[head] = a;
		}
	}

void BaseQueue::push_back(ent a)
	{
	if ( num_entries == max_entries )
		{
		resize(max_entries+chunk_size);	// make more room
		chunk_size *= 2;
		}

	++num_entries;
	if ( tail < max_entries )
		entry[tail++] = a;
	else
		{
		entry[tail] = a;
		tail = 0;
		}
	}

ent BaseQueue::pop_front()
	{
	if ( ! num_entries )
		return 0;

	--num_entries;
	if ( head < max_entries )
		return entry[head++];
	else
		{
		head = 0;
		return entry[max_entries];
		}
	}

ent BaseQueue::pop_back()
	{
	if ( ! num_entries )
		return 0;

	--num_entries;
	if ( tail )
		return entry[--tail];
	else
		{
		tail = max_entries;
		return entry[tail];
		}
	}

int BaseQueue::resize(int new_size)
	{
	if ( new_size < num_entries )
		new_size = num_entries; // do not lose any entries

	if ( new_size != max_entries )
		{
		// Note, allocate extra space, so that we can always
		// use the [max_entries] element.
		// ### Yin, why not use realloc()?
		ent* new_entry = new ent[new_size+1];

		if ( new_entry )
			{
			if ( head <= tail )
				memcpy( new_entry, entry + head,
					sizeof(ent) * num_entries );
			else
				{
				int len = num_entries - tail;
				memcpy( new_entry, entry + head,
					sizeof(ent) * len );
				memcpy( new_entry + len, entry,
					sizeof(ent) * tail );
				}
			delete [] entry;
			entry = new_entry;
			max_entries = new_size;
			head = 0;
			tail = num_entries;
			}
		else
			{ // out of memory
			}
		}

	return max_entries;
	}
