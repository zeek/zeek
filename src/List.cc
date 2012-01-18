#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include "List.h"
#include "util.h"

static const int DEFAULT_CHUNK_SIZE = 10;

BaseList::BaseList(int size)
	{
	chunk_size = DEFAULT_CHUNK_SIZE;

	if ( size < 0 )
		{
		num_entries = max_entries = 0;
		entry = 0;
		}
	else
		{
		if ( size > 0 )
			chunk_size = size;

		num_entries = 0;
		entry = (ent *) safe_malloc(chunk_size * sizeof(ent));
		max_entries = chunk_size;
		}
	}


BaseList::BaseList(BaseList& b)
	{
	max_entries = b.max_entries;
	chunk_size = b.chunk_size;
	num_entries = b.num_entries;

	if ( max_entries )
		entry = (ent *) safe_malloc(max_entries * sizeof(ent));
	else
		entry = 0;

	for ( int i = 0; i < num_entries; ++i )
		entry[i] = b.entry[i];
	}

void BaseList::sort(list_cmp_func cmp_func)
	{
	qsort(entry, num_entries, sizeof(ent), cmp_func);
	}

void BaseList::operator=(BaseList& b)
	{
	if ( this == &b )
		return;	// i.e., this already equals itself

	if ( entry )
		free(entry);

	max_entries = b.max_entries;
	chunk_size = b.chunk_size;
	num_entries = b.num_entries;

	if ( max_entries )
		entry = (ent *) safe_malloc(max_entries * sizeof(ent));
	else
		entry = 0;

	for ( int i = 0; i < num_entries; ++i )
		entry[i] = b.entry[i];
	}

void BaseList::insert(ent a)
	{
	if ( num_entries == max_entries )
		{
		resize(max_entries + chunk_size);	// make more room
		chunk_size *= 2;
		}

	for ( int i = num_entries; i > 0; --i )
		entry[i] = entry[i-1];	// move all pointers up one

	++num_entries;
	entry[0] = a;
	}

#include <stdio.h>

void BaseList::sortedinsert(ent a, list_cmp_func cmp_func)
	{
	// We optimize for the case that the new element is
	// larger than most of the current entries.

	// First append element.
	if ( num_entries == max_entries )
		{
		resize(max_entries + chunk_size);
		chunk_size *= 2;
		}

	entry[num_entries++] = a;

	// Then move it to the correct place.
	ent tmp;
	for ( int i = num_entries - 1; i > 0; --i )
		{
		if ( cmp_func(entry[i],entry[i-1]) <= 0 )
			break;

		tmp = entry[i];
		entry[i] = entry[i-1];
		entry[i-1] = tmp;
		}
	}

ent BaseList::remove(ent a)
	{
	int i;
	for ( i = 0; i < num_entries && a != entry[i]; ++i )
		;

	return remove_nth(i);
	}

ent BaseList::remove_nth(int n)
	{
	if ( n < 0 || n >= num_entries )
		return 0;

	ent old_ent = entry[n];
	--num_entries;

	for ( ; n < num_entries; ++n )
		entry[n] = entry[n+1];

	entry[n] = 0;	// for debugging
	return old_ent;
	}

void BaseList::append(ent a)
	{
	if ( num_entries == max_entries )
		{
		resize(max_entries + chunk_size);	// make more room
		chunk_size *= 2;
		}

	entry[num_entries++] = a;
	}

// Get and remove from the end of the list.
ent BaseList::get()
	{
	if ( num_entries == 0 )
		return 0;

	return entry[--num_entries];
	}


void BaseList::clear()
	{
	if ( entry )
		{
		free(entry);
		entry = 0;
		}

	num_entries = max_entries = 0;
	chunk_size = DEFAULT_CHUNK_SIZE;
	}

ent BaseList::replace(int ent_index, ent new_ent)
	{
	if ( ent_index < 0 )
		return 0;

	ent old_ent;

	if ( ent_index > num_entries - 1 )
		{ // replacement beyond the end of the list
		resize(ent_index + 1);

		for ( int i = num_entries; i < max_entries; ++i )
			entry[i] = 0;
		num_entries = max_entries;

		old_ent = 0;
		}
	else
		old_ent = entry[ent_index];

	entry[ent_index] = new_ent;

	return old_ent;
	}

int BaseList::resize(int new_size)
	{
	if ( new_size < num_entries )
		new_size = num_entries;	// do not lose any entries

	if ( new_size != max_entries )
		{
		entry = (ent*) safe_realloc((void*) entry, sizeof(ent) * new_size);
		if ( entry )
			max_entries = new_size;
		else
			max_entries = 0;
		}

	return max_entries;
	}

ent BaseList::is_member(ent e) const
	{
	int i;
	for ( i = 0; i < length() && e != entry[i]; ++i )
		;

	return (i == length()) ? 0 : e;
	}

int BaseList::member_pos(ent e) const
	{
	int i;
	for ( i = 0; i < length() && e != entry[i]; ++i )
		;

	return (i == length()) ? -1 : i;
	}
