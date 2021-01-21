// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <list>
#include "zeek/Val.h"
#include "zeek/OpaqueVal.h"

// This class implements the top-k algorithm. Or - to be more precise - an
// interpretation of it.

ZEEK_FORWARD_DECLARE_NAMESPACED(CompositeHash, zeek::detail);

namespace zeek::probabilistic::detail {

struct Element;

struct Bucket {
	uint64_t count;
	std::list<Element*> elements;

	// Iterators only get invalidated for removed elements. This one
	// points to us - so it is invalid when we are no longer there. Cute,
	// isn't it?
	std::list<Bucket*>::iterator bucketPos;
};

struct Element {
	uint64_t epsilon;
	ValPtr value;
	Bucket* parent;
};

class TopkVal : public OpaqueVal {

public:
	/**
	 * Construct a TopkVal.
	 *
	 * @param size specifies how many total elements are tracked
	 *
	 * @return A newly initialized TopkVal
	 */
	explicit TopkVal(uint64_t size);

	/**
	 * Destructor.
	 */
	~TopkVal() override;

	/**
	 * Call this when a new value is encountered. Note that on the first
	 * call, the Bro type of the value types that are counted is set. All
	 * following calls to encountered have to specify the same type.
	 *
	 * @param value The encountered element
	 */
	void Encountered(ValPtr value);

	/**
	 * Get the first *k* elements of the result vector. At the moment,
	 * this does not check if it is in the right order or if we can prove
	 * that these are the correct top-k. Use count and epsilon for this.
	 *
	 * @param k Number of top-elements to return
	 *
	 * @returns The top-k encountered elements
	 */
	VectorValPtr GetTopK(int k) const;

	/**
	 * Get the current count tracked in the top-k data structure for a
	 * certain val. Returns 0 if the val is unknown (and logs the error
	 * to reporter).
	 *
	 * @param value Bro value to get counts for
	 *
	 * @returns internal count for val, 0 if unknown
	 */
	 uint64_t GetCount(Val* value) const;

	/**
	 * Get the current epsilon tracked in the top-k data structure for a
	 * certain val.
	 *
	 * @param value Bro value to get epsilons for
	 *
	 * @returns the epsilon. Returns 0 if the val is unknown (and logs
	 * the error to reporter)
	 */
	uint64_t GetEpsilon(Val* value) const;

	/**
	 * Get the size set in the constructor
	 *
	 * @returns size of the top-k structure
	 */
	uint64_t GetSize() const { return size; }

	/**
	 * Get the sum of all counts of all tracked elements. This is equal
	 * to the number of total observations up to this moment, if no
	 * elements were pruned from the data structure.
	 *
	 * @returns sum of all counts
	 */
	uint64_t GetSum() const;

	/**
	 * Merge another top-k data structure into this one. doPrune
	 * specifies if the total count of elements is limited to size after
	 * merging. Please note, that pruning will invalidate the results of
	 * getSum.
	 *
	 * @param value TopkVal to merge into this TopkVal
	 *
	 * @param doPrune prune resulting TopkVal to size after merging
	 */
	void Merge(const TopkVal* value, bool doPrune=false);

	/**
	 * Clone the Opaque Type
	 *
	 * @param state Clone state (tracking duplicate pointers)
	 *
	 * @returns cloned TopkVal
	 */
	ValPtr DoClone(CloneState* state) override;

	DECLARE_OPAQUE_VALUE(TopkVal)

protected:
	/**
	 * Construct an empty TopkVal. Only used for deserialization
	 */
	TopkVal();

private:
	/**
	 * Increment the counter for a specific element
	 *
	 * @param e element to increment counter for
	 *
	 * @param count increment counter by this much
	 */
	void IncrementCounter(Element* e, unsigned int count = 1);

	/**
	 * get the hashkey for a specific value
	 *
	 * @param v value to generate key for
	 *
	 * @returns HashKey for value
	 */
	zeek::detail::HashKey* GetHash(Val* v) const; // this probably should go somewhere else.
	zeek::detail::HashKey* GetHash(const ValPtr& v) const
		{ return GetHash(v.get()); }

	/**
	 * Set the type that this TopK instance tracks
	 *
	 * @param t type that is tracked
	 */
	void Typify(TypePtr t);

	TypePtr type;
	zeek::detail::CompositeHash* hash;
	std::list<Bucket*> buckets;
	PDict<Element>* elementDict;
	uint64_t size; // how many elements are we tracking?
	uint64_t numElements; // how many elements do we have at the moment
	bool pruned; // was this data structure pruned?
};

} // namespace zeek::probabilistic::detail
