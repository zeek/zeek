#ifndef list_h
#define list_h

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

#include <initializer_list>
#include <utility>
#include <stdarg.h>
#include "util.h"

typedef void* ent;
typedef int (*list_cmp_func)(const void* v1, const void* v2);

class BaseList {
public:
	void clear();		// remove all entries
	int length() const	{ return num_entries; }
	int max() const		{ return max_entries; }
	int resize(int = 0);	// 0 => size to fit current number of entries

	void sort(list_cmp_func cmp_func);

	int MemoryAllocation() const
		{ return padded_sizeof(*this) + pad_size(max_entries * sizeof(ent)); }

protected:
	~BaseList()		{ free(entry); }
	explicit BaseList(int = 0);
	BaseList(const BaseList&);
	BaseList(BaseList&&);
	BaseList(const ent* arr, int n);

	BaseList& operator=(const BaseList&);
	BaseList& operator=(BaseList&&);

	void insert(ent);	// add at head of list

	// Assumes that the list is sorted and inserts at correct position.
	void sortedinsert(ent, list_cmp_func cmp_func);

	void append(ent);	// add to end of list
	ent remove(ent);	// delete entry from list
	ent remove_nth(int);	// delete nth entry from list
	ent get();		// return and remove ent at end of list
	ent last()		// return at end of list
		{ return entry[num_entries-1]; }

	// Return 0 if ent is not in the list, ent otherwise.
	ent is_member(ent) const;

	// Returns -1 if ent is not in the list, otherwise its position.
	int member_pos(ent) const;

	ent replace(int, ent);	// replace entry #i with a new value

	// Return nth ent of list (do not remove).
	ent operator[](int i) const
		{
#ifdef SAFE_LISTS
		if ( i < 0 || i > num_entries-1 )
			return 0;
		else
#endif
			return entry[i];
		}

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

	ent* entry;
	int max_entries;
	int num_entries;
	};


// List.h -- interface for class List
//	Use:	to get a list of pointers to class foo you should:
//		1) typedef foo* Pfoo; (the macros don't like explicit pointers)
//		2) declare(List,Pfoo); (declare an interest in lists of Pfoo's)
//		3) variables are declared like:
//				List(Pfoo) bar;	(bar is of type list of Pfoo's)

// For lists of "type".

#define List(type) type ## List

// For lists of pointers to "type"
#define PList(type) type ## PList

#define Listdeclare(type)						\
struct List(type) : BaseList						\
	{								\
	explicit List(type)(type ...);						\
	List(type)() : BaseList(0) {}					\
	explicit List(type)(int sz) : BaseList(sz) {}				\
	List(type)(const List(type)& l) : BaseList(l) {}		\
	List(type)(List(type)&& l) : BaseList(std::move(l)) {}		\
									\
	List(type)& operator=(const List(type)& l)					\
		{ return (List(type)&) BaseList::operator=(l); }			\
	List(type)& operator=(List(type)&& l)					\
		{ return (List(type)&) BaseList::operator=(std::move(l)); }			\
	void insert(type a)	{ BaseList::insert(ent(a)); }		\
	void sortedinsert(type a, list_cmp_func cmp_func)		\
		{ BaseList::sortedinsert(ent(a), cmp_func); }		\
	void append(type a)	{ BaseList::append(ent(a)); }		\
	type remove(type a)						\
			{ return type(BaseList::remove(ent(a))); }	\
	type remove_nth(int n)	{ return type(BaseList::remove_nth(n)); }\
	type get()		{ return type(BaseList::get()); }	\
	type last()		{ return type(BaseList::last()); }	\
	type replace(int i, type new_type)				\
		{ return type(BaseList::replace(i,ent(new_type))); }	\
	type is_member(type e) const					\
		{ return type(BaseList::is_member(ent(e))); }		\
	int member_pos(type e) const					\
		{ return BaseList::member_pos(ent(e)); }		\
									\
	type operator[](int i) const					\
		{ return type(BaseList::operator[](i)); }		\
	};								\

#define Listimplement(type)						\
List(type)::List(type)(type e1 ...) : BaseList()			\
	{								\
	append(e1);							\
	va_list ap;							\
	va_start(ap,e1);						\
	for ( type e = va_arg(ap,type); e != 0; e = va_arg(ap,type) )	\
		append(e);						\
	resize();							\
	}

#define PListdeclare(type)						\
struct PList(type) : BaseList						\
	{								\
	explicit PList(type)(type* ...);						\
	PList(type)() : BaseList(0) {}					\
	explicit PList(type)(int sz) : BaseList(sz) {}				\
	PList(type)(const PList(type)& l) : BaseList(l) {}		\
	PList(type)(PList(type)&& l) : BaseList(std::move(l)) {}		\
	PList(type)(std::initializer_list<type*> il) : BaseList((const ent*)il.begin(), il.size()) {}		\
									\
	PList(type)& operator=(const PList(type)& l)					\
		{ return (PList(type)&) BaseList::operator=(l); }			\
	PList(type)& operator=(PList(type)&& l)					\
		{ return (PList(type)&) BaseList::operator=(std::move(l)); }			\
	void insert(type* a)	{ BaseList::insert(ent(a)); }		\
	void sortedinsert(type* a, list_cmp_func cmp_func)		\
		{ BaseList::sortedinsert(ent(a), cmp_func); }		\
	void append(type* a)	{ BaseList::append(ent(a)); }		\
	type* remove(type* a)						\
		{ return (type*)BaseList::remove(ent(a)); }		\
	type* remove_nth(int n)	{ return (type*)(BaseList::remove_nth(n)); }\
	type* get()		{ return (type*)BaseList::get(); }	\
	type* operator[](int i) const					\
		{ return (type*)(BaseList::operator[](i)); }		\
	type* replace(int i, type* new_type)				\
		{ return (type*)BaseList::replace(i,ent(new_type)); }	\
	type* is_member(type* e)					\
		{ return (type*)BaseList::is_member(ent(e)); }		\
	int member_pos(type* e)						\
		{ return BaseList::member_pos(ent(e)); }		\
	};								\

#define PListimplement(type)						\
PList(type)::PList(type)(type* ep1 ...) : BaseList()			\
	{								\
	append(ep1);							\
	va_list ap;							\
	va_start(ap,ep1);						\
	for ( type* ep = va_arg(ap,type*); ep != 0;			\
	      ep = va_arg(ap,type*) )					\
		append(ep);						\
	resize();							\
	}


#define declare(metatype,type) metatype ## declare (type)

// Popular type of list: list of strings.
declare(PList,char);
typedef PList(char) name_list;

// Macro to visit each list element in turn.
#define loop_over_list(list, iterator)  \
	int iterator;	\
	for ( iterator = 0; iterator < (list).length(); ++iterator )

#endif /* list_h */
