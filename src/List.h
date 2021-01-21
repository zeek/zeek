#pragma once

// BaseList.h --
//	Interface for class BaseList, current implementation is as an
//	array of ent's.  This implementation was chosen to optimize
//	getting to the ent's rather than inserting and deleting.
//	Also pairs of append's and get's act like push's and pop's
//	and are very efficient.  The only really expensive operations
//	are inserting (but not appending), which requires pushing every
//	element up, and resizing the list, which involves getting new space
//	and moving the data.  Resizing occurs automatically when inserting
//	more elements than the list can currently hold.  Automatic
//	resizing is done by growing by GROWTH_FACTOR at a time and
//	always increases the size of the list.  Resizing to zero
//	(or to less than the current value of num_entries)
//	will decrease the size of the list to the current number of
//	elements.  Resize returns the new max_entries.
//
//	Entries must be either a pointer to the data or nonzero data with
//	sizeof(data) <= sizeof(void*).

#include <stdarg.h>
#include <initializer_list>
#include <iterator>
#include <utility>
#include <cassert>
#include "zeek/util.h"

namespace zeek {

enum class ListOrder : int { ORDERED, UNORDERED };

template<typename T, ListOrder Order = ListOrder::ORDERED>
class List {
public:

	constexpr static int DEFAULT_LIST_SIZE = 10;
	constexpr static int LIST_GROWTH_FACTOR = 2;

	~List()		{ free(entries); }
	explicit List(int size = 0)
		{
		num_entries = 0;

		if ( size <= 0 )
			{
			max_entries = 0;
			entries = nullptr;
			return;
			}

		max_entries = size;

		entries = (T*) util::safe_malloc(max_entries * sizeof(T));
		}

	List(const List& b)
		{
		max_entries = b.max_entries;
		num_entries = b.num_entries;

		if ( max_entries )
			entries = (T*) util::safe_malloc(max_entries * sizeof(T));
		else
			entries = nullptr;

		for ( int i = 0; i < num_entries; ++i )
			entries[i] = b.entries[i];
		}

	List(List&& b)
		{
		entries = b.entries;
		num_entries = b.num_entries;
		max_entries = b.max_entries;

		b.entries = nullptr;
		b.num_entries = b.max_entries = 0;
		}

	List(const T* arr, int n)
		{
		num_entries = max_entries = n;
		entries = (T*) util::safe_malloc(max_entries * sizeof(T));
		memcpy(entries, arr, n * sizeof(T));
		}

	List(std::initializer_list<T> il) : List(il.begin(), il.size()) {}

	List& operator=(const List& b)
		{
		if ( this == &b )
			return *this;

		free(entries);

		max_entries = b.max_entries;
		num_entries = b.num_entries;

		if ( max_entries )
			entries = (T *) util::safe_malloc(max_entries * sizeof(T));
		else
			entries = nullptr;

		for ( int i = 0; i < num_entries; ++i )
			entries[i] = b.entries[i];

		return *this;
		}

	List& operator=(List&& b)
		{
		if ( this == &b )
			return *this;

		free(entries);
		entries = b.entries;
		num_entries = b.num_entries;
		max_entries = b.max_entries;

		b.entries = nullptr;
		b.num_entries = b.max_entries = 0;
		return *this;
		}

	// Return nth ent of list (do not remove).
	T& operator[](int i) const
		{
		return entries[i];
		}

	void clear()		// remove all entries
		{
		free(entries);
		entries = nullptr;
		num_entries = max_entries = 0;
		}

	bool empty() const noexcept { return num_entries == 0; }
	size_t size() const noexcept { return num_entries; }

	int length() const	{ return num_entries; }
	int max() const		{ return max_entries; }
	int resize(int new_size = 0)	// 0 => size to fit current number of entries
		{
		if ( new_size < num_entries )
			new_size = num_entries;	// do not lose any entries

		if ( new_size != max_entries )
			{
			entries = (T*) util::safe_realloc((void*) entries, sizeof(T) * new_size);
			if ( entries )
				max_entries = new_size;
			else
				max_entries = 0;
			}

		return max_entries;
		}

	int MemoryAllocation() const
		{ return padded_sizeof(*this) + util::pad_size(max_entries * sizeof(T)); }

	void push_front(const T& a)
		{
		if ( num_entries == max_entries )
			resize(max_entries ? max_entries * LIST_GROWTH_FACTOR : DEFAULT_LIST_SIZE);

		for ( int i = num_entries; i > 0; --i )
			entries[i] = entries[i-1];	// move all pointers up one

		++num_entries;
		entries[0] = a;
		}

	void push_back(const T& a)
		{
		if ( num_entries == max_entries )
			resize(max_entries ? max_entries * LIST_GROWTH_FACTOR : DEFAULT_LIST_SIZE);

		entries[num_entries++] = a;
		}

	void pop_front()	{ remove_nth(0); }
	void pop_back()	{ remove_nth(num_entries-1); }

	T& front()	 { return entries[0]; }
	T& back()	 { return entries[num_entries-1]; }

	// The append method is maintained for historical/compatibility reasons.
	// (It's commonly used in the event generation API)
	void append(const T& a)	// add to end of list
		{
		push_back(a);
		}

	bool remove(const T& a)	// delete entry from list
		{
		int pos = member_pos(a);
		if ( pos != -1 )
			{
			remove_nth(pos);
			return true;
			}

		return false;
		}

	T remove_nth(int n)	// delete nth entry from list
		{
		assert(n >=0 && n < num_entries);

		T old_ent = entries[n];

		// For data where we don't care about ordering, we don't care about keeping
		// the list in the same order when removing an element. Just swap the last
		// element with the element being removed.
		if constexpr ( Order == ListOrder::ORDERED )
			{
			--num_entries;

			for ( ; n < num_entries; ++n )
				entries[n] = entries[n+1];
			}
		else
			{
			entries[n] = entries[num_entries - 1];
			--num_entries;
			}

		return old_ent;
		}

	// Return 0 if ent is not in the list, ent otherwise.
	bool is_member(const T& a) const
		{
		int pos = member_pos(a);
		return pos != -1;
		}

	// Returns -1 if ent is not in the list, otherwise its position.
	int member_pos(const T& e) const
		{
		int i;
		for ( i = 0; i < length() && e != entries[i]; ++i )
			;

		return (i == length()) ? -1 : i;
		}

	T replace(int ent_index, const T& new_ent)	// replace entry #i with a new value
		{
		if ( ent_index < 0 )
			return T{};

		T old_ent{};

		if ( ent_index > num_entries - 1 )
			{ // replacement beyond the end of the list
			resize(ent_index + 1);

			for ( int i = num_entries; i < max_entries; ++i )
				entries[i] = T{};
			num_entries = max_entries;
			}
		else
			old_ent = entries[ent_index];

		entries[ent_index] = new_ent;

		return old_ent;
		}

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

	// This could essentially be an std::vector if we wanted.  Some
	// reasons to maybe not refactor to use std::vector ?
	//
	//  - Harder to use a custom growth factor.  Also, the growth
	//    factor would be implementation-specific, taking some control over
	//    performance out of our hands.
	//
	//  - It won't ever take advantage of realloc's occasional ability to
	//    grow in-place.
	//
	//  - Combine above point this with lack of control of growth
	//    factor means the common choice of 2x growth factor causes
	//    a growth pattern that crawls forward in memory with no possible
	//    re-use of previous chunks (the new capacity is always larger than
	//    all previously allocated chunks combined).  This point and
	//    whether 2x is empirically an issue still seems debated (at least
	//    GCC seems to stand by 2x as empirically better).
	//
	//  - Sketchy shrinking behavior: standard says that requests to
	//    shrink are non-binding (it's expected implementations heed, but
	//    still not great to have no guarantee).  Also, it would not take
	//    advantage of realloc's ability to contract in-place, it would
	//    allocate-and-copy.

	T* entries;
	int max_entries;
	int num_entries;
	};


// Specialization of the List class to store pointers of a type.
template<typename T, ListOrder Order = ListOrder::ORDERED>
using PList = List<T*, Order>;

// Popular type of list: list of strings.
using name_list = PList<char>;

} // namespace zeek

// Macro to visit each list element in turn.
#define loop_over_list(list, iterator)  \
	int iterator;	\
	for ( iterator = 0; iterator < (list).length(); ++iterator )
