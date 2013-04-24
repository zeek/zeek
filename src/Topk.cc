// See the file "COPYING" in the main distribution directory for copyright.

#include "Topk.h"
#include "CompHash.h"
#include "Reporter.h"
#include "Serializer.h"


namespace Topk {

IMPLEMENT_SERIAL(TopkVal, SER_TOPK_VAL);

static void topk_element_hash_delete_func(void* val)
	{
	Element* e = (Element*) val;
	delete e;
	}

Element::~Element() 
	{
	if ( value ) 
		Unref(value);
	value=0;
	}

HashKey* TopkVal::GetHash(Val* v) const
	{
	TypeList* tl = new TypeList(v->Type());
	tl->Append(v->Type());
	CompositeHash* topk_hash = new CompositeHash(tl);
	Unref(tl);

	HashKey* key = topk_hash->ComputeHash(v, 1);
	assert(key);
	return key;
	}

TopkVal::TopkVal(uint64 arg_size) : OpaqueVal(new OpaqueType("topk"))
	{
	elementDict = new PDict(Element);
	elementDict->SetDeleteFunc(topk_element_hash_delete_func);
	size = arg_size;
	type = 0;
	numElements = 0;
	}

TopkVal::TopkVal() : OpaqueVal(new OpaqueType("topk"))
	{
	elementDict = new PDict(Element);
	elementDict->SetDeleteFunc(topk_element_hash_delete_func);
	size = 0;
	type = 0;
	numElements = 0;
	}

TopkVal::~TopkVal()
	{
	elementDict->Clear();
	delete elementDict;

	// now all elements are already gone - delete the buckets
	std::list<Bucket*>::iterator bi = buckets.begin();
	while ( bi != buckets.end() )
		{
		delete *bi;
		bi++;
		}

	if ( type ) 
		Unref(type);
	type = 0;
	}


bool TopkVal::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_TOPK_VAL, OpaqueVal);

	bool v = true;

	v &= SERIALIZE(size);
	v &= SERIALIZE(numElements);
	bool type_present = (type != 0);
	v &= SERIALIZE(type_present);
	if ( type_present )
		v &= type->Serialize(info);
	else 
		assert(numElements == 0);

	int i = 0;
	std::list<Bucket*>::const_iterator it = buckets.begin();
	while ( it != buckets.end() ) 
		{
		Bucket* b = *it;
		uint32_t elements_count = b->elements.size();
		v &= SERIALIZE(elements_count);
		v &= SERIALIZE(b->count);
		std::list<Element*>::const_iterator eit = b->elements.begin();
		while ( eit != b->elements.end() ) 
			{
			Element* element = *eit;
			v &= SERIALIZE(element->epsilon);
			v &= element->value->Serialize(info);

			eit++;
			i++;
			}

		it++;
		}

	assert(i == numElements);

	return v;
	}

bool TopkVal::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(OpaqueVal);

	bool v = true;

	v &= UNSERIALIZE(&size);
	v &= UNSERIALIZE(&numElements);
	bool type_present = false;
	v &= UNSERIALIZE(&type_present);
	if ( type_present ) 
		{
		type = BroType::Unserialize(info);
		assert(type);
		}
	else
		assert(numElements == 0);

	int i = 0;
	while ( i < numElements ) 
		{
		Bucket* b = new Bucket();
		uint32_t elements_count;
		v &= UNSERIALIZE(&elements_count);
		v &= UNSERIALIZE(&b->count);
		b->bucketPos = buckets.insert(buckets.end(), b);

		for ( int j = 0; j < elements_count; j++ ) 
			{
			Element* e = new Element();
			v &= UNSERIALIZE(&e->epsilon);
			e->value = Val::Unserialize(info, type);
			e->parent = b;

			b->elements.insert(b->elements.end(), e);

			HashKey* key = GetHash(e->value);
			assert (  elementDict->Lookup(key) == 0 );

			elementDict->Insert(key, e);
			delete key;

		
			i++;
			}
		}

	assert(i == numElements);

	return v;
	}


VectorVal* TopkVal::getTopK(int k) const // returns vector
	{
	if ( numElements == 0 )
		{
		reporter->Error("Cannot return topk of empty");
		return 0;
		}

	TypeList* vector_index = new TypeList(type);
	vector_index->Append(type);
	VectorType* v = new VectorType(vector_index);
	VectorVal* t = new VectorVal(v);

	// this does no estimation if the results is correct!
	// in any case - just to make this future-proof (and I am lazy) - this can return more than k.
	
	int read = 0;
	std::list<Bucket*>::const_iterator it = buckets.end();
	it--;
	while (read < k )
		{
		//printf("Bucket %llu\n", (*it)->count);
		std::list<Element*>::iterator eit = (*it)->elements.begin();
		while (eit != (*it)->elements.end() ) 
			{
			//printf("Size: %ld\n", (*it)->elements.size());
			t->Assign(read, (*eit)->value->Ref());
			read++;
			eit++;
			}

		if ( it == buckets.begin() )
			break;

		it--;
		}


	Unref(v);
	return t;
	}

uint64_t TopkVal::getCount(Val* value) const
	{
	HashKey* key = GetHash(value);
	Element* e = (Element*) elementDict->Lookup(key);

	if ( e == 0 ) 
		{
		reporter->Error("getCount for element that is not in top-k");	
		return 0;
		}

	return e->parent->count;
	}

uint64_t TopkVal::getEpsilon(Val* value) const
	{
	HashKey* key = GetHash(value);
	Element* e = (Element*) elementDict->Lookup(key);

	if ( e == 0 ) 
		{
		reporter->Error("getEpsilon for element that is not in top-k");	
		return 0;
		}

	return e->epsilon;
	}
	
void TopkVal::Encountered(Val* encountered) 
	{
	// ok, let's see if we already know this one.
	
	//printf("NumElements: %d\n", numElements);
	// check type compatibility
	if ( numElements == 0 ) 
		type = encountered->Type()->Ref()->Ref();
	else
		if ( !same_type(type, encountered->Type()) ) 
			{
			reporter->Error("Trying to add element to topk with differing type from other elements");
			return;
			}

	
	// Step 1 - get the hash.
	HashKey* key = GetHash(encountered);
	Element* e = (Element*) elementDict->Lookup(key);

	if ( e == 0 ) 
		{
		e = new Element();
		e->epsilon = 0;
		e->value = encountered->Ref(); // or no ref?


		// well, we do not know this one yet...
		if ( numElements < size ) 
			{
			// brilliant. just add it at position 1
			if ( buckets.size() == 0 || (*buckets.begin())->count > 1 ) 
				{
				Bucket* b = new Bucket();
				b->count = 1;
				std::list<Bucket*>::iterator pos = buckets.insert(buckets.begin(), b);
				b->bucketPos = pos;
				b->elements.insert(b->elements.end(), e);
				e->parent = b;
				}
			else 
				{
				Bucket* b = *buckets.begin();
				assert(b->count == 1);
				b->elements.insert(b->elements.end(), e);
				e->parent = b;
				}

			elementDict->Insert(key, e);
			numElements++;
			delete key;
			return; // done. it is at pos 1.
			}
		else 
			{
			// replace element with min-value
			Bucket* b = *buckets.begin(); // bucket with smallest elements
			// evict oldest element with least hits.
			assert(b->elements.size() > 0);
			HashKey* deleteKey = GetHash((*(b->elements.begin()))->value);
			b->elements.erase(b->elements.begin());
			Element* deleteElement = (Element*) elementDict->RemoveEntry(deleteKey);
			assert(deleteElement); // there has to have been a minimal element...
			delete deleteElement;
			delete deleteKey;
			// and add the new one to the end
			e->epsilon = b->count;
			b->elements.insert(b->elements.end(), e);
			elementDict->Insert(key, e);
			e->parent = b;
			// fallthrough, increment operation has to run!
			}

		}

	// ok, we now have an element in e
	delete key;
	IncrementCounter(e); // well, this certainly was anticlimatic.
	
	}

void TopkVal::IncrementCounter(Element* e) 
	{
	Bucket* currBucket = e->parent;
	uint64 currcount = currBucket->count;
	
	// well, let's test if there is a bucket for currcount++
	std::list<Bucket*>::iterator bucketIter = currBucket->bucketPos;

	Bucket* nextBucket = 0;

	bucketIter++;

	if ( bucketIter != buckets.end() ) 
		{
		if ( (*bucketIter)->count == currcount+1 )
			nextBucket = *bucketIter;
		}

	if ( nextBucket == 0 ) 
		{
		// the bucket for the value that we want does not exist.
		// create it...

		Bucket* b = new Bucket();
		b->count = currcount+1;

		std::list<Bucket*>::iterator nextBucketPos = buckets.insert(bucketIter, b);
		b->bucketPos = nextBucketPos; // and give it the iterator we know now.

		nextBucket = b;
		}

	// ok, now we have the new bucket in nextBucket. Shift the element over...
	currBucket->elements.remove(e);
	nextBucket->elements.insert(nextBucket->elements.end(), e);

	e->parent = nextBucket;

	// if currBucket is empty, we have to delete it now
	if ( currBucket->elements.size() == 0 ) 
		{
		buckets.remove(currBucket);
		delete currBucket;
		currBucket = 0;
		}

	
	}

};
