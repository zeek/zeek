// A simple but fast data structure for sets of integers.
// Only supported operations are insert, remove and membership test.
//
// It's implemented via a bitmap so the memory usage increases linearly
// with max(set).

#pragma once

#include <string.h>

namespace zeek::detail {

class IntSet {
public:
	// n is a hint for the value of the largest integer.
	explicit IntSet(unsigned int n = 1);
	~IntSet();

	void Insert(unsigned int i);
	void Remove(unsigned int i);
	bool Contains(unsigned int i) const;

	void Clear();

private:
	void Expand(unsigned int i);

	unsigned int size;
	unsigned char* set;
	};

inline IntSet::IntSet(unsigned int n)
	{
	size = n / 8 + 1;
	set = new unsigned char[size];
	memset(set, 0, size);
	}

inline IntSet::~IntSet()
	{
	delete [] set;
	}

inline void IntSet::Insert(unsigned int i)
	{
	if ( i / 8 >= size )
		Expand(i);

	set[i / 8] |= (1 << (i % 8));
	}

inline void IntSet::Remove(unsigned int i)
	{
	if ( i / 8 >= size )
		Expand(i);
	else
		set[i / 8] &= ~(1 << (i % 8));
	}

inline bool IntSet::Contains(unsigned int i) const
	{
	return i / 8 < size ? set[i / 8] & (1 << (i % 8)) : false;
	}

inline void IntSet::Clear()
	{
	memset(set, 0, size);
	}

} // namespace zeek::detail
