// See the file "COPYING" in the main distribution directory for copyright.

#ifndef topk_h
#define topk_h

#include <list>
#include "Val.h"
#include "CompHash.h"

// This class implements the top-k algorithm. Or - to be more precise - my interpretation of it.

namespace Topk {

struct Element;

struct Bucket {
	uint64 count;
	std::list<Element*> elements;
	std::list<Bucket*>::iterator bucketPos; // iterators only get invalidated for removed elements. This one points to us - so it is invalid when we are no longer there. Cute, isn't it?
};

struct Element {
	uint64 epsilon;
	Val* value;
	Bucket* parent;

	~Element();
};


declare(PDict, Element);

class Topk {

public:
	Topk(uint64 size);
	~Topk();
	void Encountered(Val* value); // we saw something
	VectorVal* getTopK(int k); // returns vector

private:
	void IncrementCounter(Element* e);
	HashKey* GetHash(Val*); // this probably should go somewhere else.
		
	BroType* type;
	std::list<Bucket*> buckets;
	PDict(Element)* elementDict;
	uint64 size; // how many elements are we tracking?
	uint64 numElements; // how many elements do we have at the moment


};

};

#endif
