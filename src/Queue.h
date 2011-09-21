// See the file "COPYING" in the main distribution directory for copyright.

#ifndef queue_h
#define queue_h

// BaseQueue.h --
//	Interface for class BaseQueue, current implementation is as an
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

#include "List.h"

class BaseQueue {
public:
	~BaseQueue()		{ delete[] entry; }

	int length() const	{ return num_entries; }
	int resize(int = 0);	// 0 => size to fit current number of entries

	// remove all entries without delete[] entry
	void clear()		{ head = tail = num_entries = 0; }

	// helper functions for iterating over queue
	int front() const	{ return head; }
	int back() const	{ return tail; }
	void incr(int& index)	{ index < max_entries ? ++index : index = 0; }

protected:
	BaseQueue(int = 0);

	void push_front(ent);	// add in front of queue
	void push_back(ent);	// add at end of queue
	ent pop_front();	// return and remove the front of queue
	ent pop_back();		// return and remove the end of queue

	// return nth *PHYSICAL* entry of queue (do not remove)
	ent operator[](int i) const	{ return entry[i]; }

	ent* entry;
	int chunk_size;		// increase size by this amount when necessary
	int max_entries;	// entry's index range: 0 .. max_entries
	int num_entries;
	int head;	// beginning of the queue in the ring
	int tail;	// just beyond the end of the queue in the ring
	};

// Queue.h -- interface for class Queue
//	Use:	to get a list of pointers to class foo you should:
//		1) declare(PQueue,foo); (declare interest in lists of foo*'s)
//		2) variables are declared like:
//			PQueue(foo) bar; (bar is of type list of foo*'s)

// For queues of "type"
#define Queue(type) type ## Queue

// For queues of pointers to "type"
#define PQueue(type) type ## PQueue

#define Queuedeclare(type)						\
struct Queue(type) : BaseQueue						\
	{								\
	Queue(type)() : BaseQueue(0) {}					\
	Queue(type)(int sz) : BaseQueue(sz) {}				\
									\
	void push_front(type a)	{ BaseQueue::push_front(ent(a)); }	\
	void push_back(type a)	{ BaseQueue::push_back(ent(a)); }	\
	type pop_front()	{ return type(BaseQueue::pop_front()); }\
	type pop_back()		{ return type(BaseQueue::pop_back()); }	\
									\
	type operator[](int i) const					\
		{ return type(BaseQueue::operator[](i)); }		\
	};								\

#define PQueuedeclare(type)						\
struct PQueue(type) : BaseQueue						\
	{								\
	PQueue(type)() : BaseQueue(0) {}				\
	PQueue(type)(int sz) : BaseQueue(sz) {}				\
									\
	void push_front(type* a){ BaseQueue::push_front(ent(a)); }	\
	void push_back(type* a)	{ BaseQueue::push_back(ent(a)); }	\
	type* pop_front()						\
		{ return (type*)BaseQueue::pop_front(); }		\
	type* pop_back()							\
		{ return (type*)BaseQueue::pop_back(); }			\
									\
	type* operator[](int i) const					\
		{ return (type*)BaseQueue::operator[](i); }		\
	};								\

// Macro to visit each queue element in turn.
#define loop_over_queue(queue, iterator)				\
	int iterator;							\
	for ( iterator = (queue).front(); iterator != (queue).back();	\
		(queue).incr(iterator) )				\

#endif /* queue_h */
