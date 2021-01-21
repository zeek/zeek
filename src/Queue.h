// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string.h>
#include <iterator>

// Queue.h --
//	Interface for class Queue, current implementation is as an
//	array of ent's.  This implementation was chosen to optimize
//	getting to the ent's rather than inserting and deleting.
//	Also push's and pop's from the front or the end of the queue
//	are very efficient.  The only really expensive operation
//	is resizing the list, which involves getting new space
//	and moving the data.  Resizing occurs automatically when inserting
//	more elements than the list can currently hold.  Automatic
//	resizing is done one "chunk_size" of elements at a time and
//	always increases the size of the list.  Resizing to zero
//	(or to less than the current value of num_entries)
//	will decrease the size of the list to the current number of
//	elements.  Resize returns the new max_entries.
//
//	Entries must be either a pointer to the data or nonzero data with
//	sizeof(data) <= sizeof(void*).

namespace zeek {

template<typename T>
class Queue {
public:
	explicit Queue(int size = 0)
		{
		const int DEFAULT_CHUNK_SIZE = 10;
		chunk_size = DEFAULT_CHUNK_SIZE;

		head = tail = num_entries = 0;

		if ( size < 0 )
			{
			entries = new T[1];
			max_entries = 0;
			}
		else
			{
			if ( (entries = new T[chunk_size+1]) )
				max_entries = chunk_size;
			else
				{
				entries = new T[1];
				max_entries = 0;
				}
			}
		}

	~Queue()		{ delete[] entries; }

	int length() const	{ return num_entries; }
	int resize(int new_size = 0)	// 0 => size to fit current number of entries
		{
		if ( new_size < num_entries )
			new_size = num_entries; // do not lose any entries

		if ( new_size != max_entries )
			{
			// Note, allocate extra space, so that we can always
			// use the [max_entries] element.
			// ### Yin, why not use realloc()?
			T* new_entries = new T[new_size+1];

			if ( new_entries )
				{
				if ( head <= tail )
					memcpy( new_entries, entries + head,
						sizeof(T) * num_entries );
				else
					{
					int len = num_entries - tail;
					memcpy( new_entries, entries + head,
						sizeof(T) * len );
					memcpy( new_entries + len, entries,
						sizeof(T) * tail );
					}
				delete [] entries;
				entries = new_entries;
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

	// remove all entries without delete[] entry
	void clear()		{ head = tail = num_entries = 0; }

	// helper functions for iterating over queue
	T& front()	{ return entries[head]; }
	T& back()	{ return entries[tail]; }
	const T& front() const	{ return entries[head]; }
	const T& back() const	{ return entries[tail]; }

	void push_front(const T& a)	// add in front of queue
		{
		if ( num_entries == max_entries )
			{
			resize(max_entries+chunk_size);	// make more room
			chunk_size *= 2;
			}

		++num_entries;
		if ( head )
			entries[--head] = a;
		else
			{
			head = max_entries;
			entries[head] = a;
			}
		}

	void push_back(const T& a)	// add at end of queue
		{
		if ( num_entries == max_entries )
			{
			resize(max_entries+chunk_size);	// make more room
			chunk_size *= 2;
			}

		++num_entries;
		if ( tail < max_entries )
			entries[tail++] = a;
		else
			{
			entries[tail] = a;
			tail = 0;
			}
		}

	void pop_front()
		{
		--num_entries;
		if ( head < max_entries )
			head++;
		else
			head = 0;
		}

	void pop_back()
		{
		--num_entries;
		if ( tail )
			--tail;
		else
			tail = max_entries;
		}

	// return nth *PHYSICAL* entry of queue (do not remove)
	T& operator[](int i) const	{ return entries[i]; }

	// Type traits needed for some of the std algorithms to work
	using value_type = T;
	using pointer = T*;
	using const_pointer = const T*;

	// Iterator support
	using iterator = pointer;
	using const_iterator = const_pointer;
	using reverse_iterator = std::reverse_iterator<iterator>;
	using const_reverse_iterator = std::reverse_iterator<const_iterator>;

	iterator begin() { return entries; }
	iterator end() { return entries + num_entries; }
	const_iterator begin() const { return entries; }
	const_iterator end() const { return entries + num_entries; }
	const_iterator cbegin() const { return entries; }
	const_iterator cend() const { return entries + num_entries; }

	reverse_iterator rbegin() { return reverse_iterator{end()}; }
	reverse_iterator rend() { return reverse_iterator{begin()}; }
	const_reverse_iterator rbegin() const { return const_reverse_iterator{end()}; }
	const_reverse_iterator rend() const { return const_reverse_iterator{begin()}; }
	const_reverse_iterator crbegin() const { return rbegin(); }
	const_reverse_iterator crend() const { return rend(); }

protected:

	T* entries;
	int chunk_size;		// increase size by this amount when necessary
	int max_entries;	// entry's index range: 0 .. max_entries
	int num_entries;
	int head;	// beginning of the queue in the ring
	int tail;	// just beyond the end of the queue in the ring
	};


template<typename T>
using PQueue = Queue<T*>;

} // namespace zeek
