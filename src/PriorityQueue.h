// See the file "COPYING" in the main distribution directory for copyright.

#ifndef __PriorityQueue__
#define __PriorityQueue__

#include <math.h>

class PriorityQueue;

class PQ_Element {
public:
	PQ_Element(double t)	{ time = t; offset = -1; }
	virtual ~PQ_Element()	{ }

	double Time() const	{ return time; }

	int Offset() const	{ return offset; }
	void SetOffset(int off)	{ offset = off; }

	void MinimizeTime()	{ time = -HUGE_VAL; }

protected:
	PQ_Element()		{ }
	double time;
	int offset;
};

class PriorityQueue {
public:
	PriorityQueue(int initial_size = 16);
	~PriorityQueue();

	// Returns the top of queue, or nil if the queue is empty.
	PQ_Element* Top() const
		{
		if ( heap_size == 0 )
			return 0;
		else
			return heap[0];
		}

	// Removes (and returns) top of queue.  Returns nil if the queue
	// is empty.
	PQ_Element* Remove();

	// Removes element e.  Returns e, or nil if e wasn't in the queue.
	// Note that e will be modified via MinimizeTime().
	PQ_Element* Remove(PQ_Element* e);

	// Add a new element to the queue.  Returns 0 on failure (not enough
	// memory to add the element), 1 on success.
	int Add(PQ_Element* e);

	int Size() const	{ return heap_size; }
	int PeakSize() const	{ return peak_heap_size; }

protected:
	int Resize(int new_size);

	void BubbleUp(int bin);
	void BubbleDown(int bin);

	int Parent(int bin) const
		{
		return bin >> 1;
		}

	int LeftChild(int bin) const
		{
		return bin << 1;
		}

	int RightChild(int bin) const
		{
		return LeftChild(bin) + 1;
		}

	void SetElement(int bin, PQ_Element* e)
		{
		heap[bin] = e;
		e->SetOffset(bin);
		}

	void Swap(int bin1, int bin2)
		{
		PQ_Element* t = heap[bin1];
		SetElement(bin1, heap[bin2]);
		SetElement(bin2, t);
		}

	PQ_Element** heap;
	int heap_size;
	int peak_heap_size;
	int max_heap_size;
};

#endif
