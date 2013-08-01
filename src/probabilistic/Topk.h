// See the file "COPYING" in the main distribution directory for copyright.

#ifndef topk_h
#define topk_h

#include <list>
#include "Val.h"
#include "CompHash.h"
#include "OpaqueVal.h"

// This class implements the top-k algorithm. Or - to be more precise - an
// interpretation of it.

namespace probabilistic {

struct Element;

struct Bucket {
	uint64 count;
	std::list<Element*> elements;

	// iterators only get invalidated for removed elements. This one
	// points to us - so it is invalid when we are no longer there. Cute,
	// isn't it?
	std::list<Bucket*>::iterator bucketPos;
};

struct Element {
	uint64 epsilon;
	Val* value;
	Bucket* parent;

	~Element();
};

declare(PDict, Element);

class TopkVal : public OpaqueVal {

public:
	// Initialize a TopkVal. Size specifies how many total elements are
	// tracked
	TopkVal(uint64 size);
	~TopkVal();

	// Call this, when a new value is encountered. Note that on the first call,
	// the Bro-Type of the value types that are counted is set. All following calls
	// to encountered have to specify the same type
	void Encountered(Val* value);

	// Return the first k elements of the result vector. At the moment, this does
	// not check if it is in the right order or if we can prove that these are
	// the correct top-k. Use count and epsilon for this.
	VectorVal* getTopK(int k) const; // returns vector

	// Get the current count tracked in the top-k data structure for a certain val.
	// Returns 0 if the val is unknown (and logs the error to reporter)
	uint64_t getCount(Val* value) const;

	// Get the current epsilon tracked in the top-k data structure for a certain val.
	// Returns 0 if the val is unknown (and logs the error to reporter)
	uint64_t getEpsilon(Val* value) const;

	// Get the size set in the constructor
	uint64_t getSize() const { return size; }

	// Get the sum of all counts of all tracked elements. This is equal to the number
	// of total observations up to this moment, if no elements were pruned from the data
	// structure.
	uint64_t getSum() const;

	// Merge another top-k data structure in this one.
	// doPrune specifies if the total count of elements is limited to size after
	// merging.
	// Please note, that pruning will invalidate the results of getSum.
	void Merge(const TopkVal* value, bool doPrune=false);

protected:
	TopkVal(); // for deserialize

private:
	void IncrementCounter(Element* e, unsigned int count = 1);
	HashKey* GetHash(Val*) const; // this probably should go somewhere else.

	BroType* type;
	std::list<Bucket*> buckets;
	PDict(Element)* elementDict;
	uint64 size; // how many elements are we tracking?
	uint64 numElements; // how many elements do we have at the moment
	bool pruned; // was this data structure pruned?

	DECLARE_SERIAL(TopkVal);
};

};

#endif
