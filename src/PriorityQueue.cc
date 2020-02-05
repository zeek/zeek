// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <stdio.h>
#include <stdlib.h>

#include "PriorityQueue.h"
#include "Reporter.h"
#include "util.h"

PriorityQueue::PriorityQueue(int initial_size)
	{
	max_heap_size = initial_size;
	heap = new PQ_Element*[max_heap_size];
	peak_heap_size = heap_size = cumulative_num = 0;
	}

PriorityQueue::~PriorityQueue()
	{
	for ( int i = 0; i < heap_size; ++i )
		delete heap[i];

	delete [] heap;
	}

PQ_Element* PriorityQueue::Remove()
	{
	if ( heap_size == 0 )
		return nullptr;

	PQ_Element* top = heap[0];

	--heap_size;
	SetElement(0, heap[heap_size]);
	BubbleDown(0);

	top->SetOffset(-1);	// = not in heap
	return top;
	}

PQ_Element* PriorityQueue::Remove(PQ_Element* e)
	{
	if ( e->Offset() < 0 || e->Offset() >= heap_size ||
	     heap[e->Offset()] != e )
		return nullptr;	// not in heap

	e->MinimizeTime();
	BubbleUp(e->Offset());

	PQ_Element* e2 = Remove();

	if ( e != e2 )
		reporter->InternalError("inconsistency in PriorityQueue::Remove");

	return e2;
	}

bool PriorityQueue::Add(PQ_Element* e)
	{
	SetElement(heap_size, e);

	BubbleUp(heap_size);

	++cumulative_num;

	if ( ++heap_size > peak_heap_size )
		peak_heap_size = heap_size;

	if ( heap_size >= max_heap_size )
		return Resize(max_heap_size * 2);
	else
		return true;
	}

bool PriorityQueue::Resize(int new_size)
	{
	PQ_Element** tmp = new PQ_Element*[new_size];
	for ( int i = 0; i < max_heap_size; ++i )
		tmp[i] = heap[i];

	delete [] heap;
	heap = tmp;

	max_heap_size = new_size;

	return heap != nullptr;
	}

void PriorityQueue::BubbleUp(int bin)
	{
	if ( bin == 0 )
		return;

	int p = Parent(bin);
	if ( heap[p]->Time() > heap[bin]->Time() )
		{
		Swap(p, bin);
		BubbleUp(p);
		}
	}

void PriorityQueue::BubbleDown(int bin)
	{
	double v = heap[bin]->Time();

	int l = LeftChild(bin);
	int r = RightChild(bin);

	if ( l >= heap_size )
		return;		// No children.

	if ( r >= heap_size )
		{ // Just a left child.
		if ( heap[l]->Time() < v )
			Swap(l, bin);
		}

	else
		{
		double lv = heap[l]->Time();
		double rv = heap[r]->Time();

		if ( lv < rv )
			{
			if ( lv < v )
				{
				Swap(l, bin);
				BubbleDown(l);
				}
			}

		else if ( rv < v )
			{
			Swap(r, bin);
			BubbleDown(r);
			}
		}
	}
