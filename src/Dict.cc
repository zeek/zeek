// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/Dict.h"

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif
#include <algorithm>
#include <signal.h>
#include <climits>
#include <fstream>

#include "zeek/3rdparty/doctest.h"

#include "zeek/Reporter.h"
#include "zeek/util.h"

#if defined(DEBUG) && defined(ZEEK_DICT_DEBUG)
#define ASSERT_VALID(o)	o->AssertValid()
#else
#define ASSERT_VALID(o)
#endif//DEBUG

namespace zeek {

class [[deprecated("Remove in v5.1. Use the standard-library-compatible version of iteration.")]] IterCookie {
public:
	IterCookie(Dictionary* d) : d(d) {}

	Dictionary* d = nullptr;
	bool robust = false;

	// Index for the next valid entry. -1 is the default, meaning we haven't started
	// iterating yet.
	int next = -1; //index for next valid entry. -1 is default not started yet.

	// Tracks the new entries inserted while iterating. Only used for robust cookies.
	std::vector<detail::DictEntry>* inserted = nullptr;

	// Tracks the entries already visited but were moved across the next iteration
	// point due to an insertion. Only used for robust cookies.
	std::vector<detail::DictEntry>* visited = nullptr;

	void MakeRobust()
		{
		// IterCookies can't be made robust after iteration has started.
		ASSERT(next < 0);
		ASSERT(d && d->cookies);

		robust = true;
		inserted = new std::vector<detail::DictEntry>();
		visited = new std::vector<detail::DictEntry>();
		d->cookies->push_back(this);
		}

	void AssertValid() const
		{
		ASSERT(d && -1 <= next && next <= d->Capacity());
		ASSERT(( ! robust && ! inserted && ! visited ) || ( robust && inserted && visited ));
		}

	~IterCookie()
		{
		ASSERT_VALID(this);
		if( robust )
			{
			d->cookies->erase(std::remove(d->cookies->begin(), d->cookies->end(), this), d->cookies->end());
			delete inserted;
			delete visited;
			}
		}
	};

// namespace detail

TEST_SUITE_BEGIN("Dict");

TEST_CASE("dict construction")
	{
	PDict<int> dict;
	CHECK(! dict.IsOrdered());
	CHECK(dict.Length() == 0);

	PDict<int> dict2(ORDERED);
	CHECK(dict2.IsOrdered());
	CHECK(dict2.Length() == 0);
	}

TEST_CASE("dict operation")
	{
	PDict<uint32_t> dict;

	uint32_t val = 10;
	uint32_t key_val = 5;

	detail::HashKey* key = new detail::HashKey(key_val);
	dict.Insert(key, &val);
	CHECK(dict.Length() == 1);

	detail::HashKey* key2 = new detail::HashKey(key_val);
	uint32_t* lookup = dict.Lookup(key2);
	CHECK(*lookup == val);

	dict.Remove(key2);
	CHECK(dict.Length() == 0);
	uint32_t* lookup2 = dict.Lookup(key2);
	CHECK(lookup2 == (uint32_t*)0);
	delete key2;

	CHECK(dict.MaxLength() == 1);
	CHECK(dict.NumCumulativeInserts() == 1);

	dict.Insert(key, &val);
	dict.Remove(key);

	CHECK(dict.MaxLength() == 1);
	CHECK(dict.NumCumulativeInserts() == 2);

	uint32_t val2 = 15;
	uint32_t key_val2 = 25;
	key2 = new detail::HashKey(key_val2);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);
	CHECK(dict.Length() == 2);
	CHECK(dict.NumCumulativeInserts() == 4);

	dict.Clear();
	CHECK(dict.Length() == 0);

	delete key;
	delete key2;
	}

TEST_CASE("dict nthentry")
	{
	PDict<uint32_t> unordered(UNORDERED);
	PDict<uint32_t> ordered(ORDERED);

	uint32_t val = 15;
	uint32_t key_val = 5;
	detail::HashKey* okey = new detail::HashKey(key_val);
	detail::HashKey* ukey = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	detail::HashKey* okey2 = new detail::HashKey(key_val2);
	detail::HashKey* ukey2 = new detail::HashKey(key_val2);

	unordered.Insert(ukey, &val);
	unordered.Insert(ukey2, &val2);

	ordered.Insert(okey, &val);
	ordered.Insert(okey2, &val2);

	// NthEntry returns null for unordered dicts
	uint32_t* lookup = unordered.NthEntry(0);
	CHECK(lookup == (uint32_t*)0);

	// Ordered dicts are based on order of insertion, nothing about the
	// data itself
	lookup = ordered.NthEntry(0);
	CHECK(*lookup == 15);

	delete okey;
	delete okey2;
	delete ukey;
	delete ukey2;
	}

TEST_CASE("dict iteration")
	{
	PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	detail::HashKey* key = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	detail::HashKey* key2 = new detail::HashKey(key_val2);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	detail::HashKey* it_key;
	IterCookie* it = dict.InitForIteration();
	CHECK(it != nullptr);
	int count = 0;

	while ( uint32_t* entry = dict.NextEntry(it_key, it) )
		{
		switch ( count )
			{
			case 0:
				// The DictEntry constructor typecasts this down to a uint32_t, so
				// we can't just check the value directly.
				// Explanation: hash_t is 64bit, open-dict only uses 32bit hash to
				// save space for each item (24 bytes aligned). OpenDict has table
				// size of 2^N and only take the lower bits of the hash. (The
				// original hash takes transformation in FibHash() to map into a
				// smaller 2^N range).
				CHECK(it_key->Hash() == (uint32_t)key2->Hash());
				CHECK(*entry == 10);
				break;
			case 1:
				CHECK(it_key->Hash() == (uint32_t)key->Hash());
				CHECK(*entry == 15);
				break;
			default:
				break;
			}
		count++;

		delete it_key;
		}

	CHECK(count == 2);

#pragma GCC diagnostic pop

	delete key;
	delete key2;
	}

TEST_CASE("dict new iteration")
	{
	PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	detail::HashKey* key = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	detail::HashKey* key2 = new detail::HashKey(key_val2);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

	int count = 0;

	for ( const auto& entry : dict )
		{
		auto* v = static_cast<uint32_t*>(entry.value);
		uint64_t k = *(uint32_t*) entry.GetKey();

		switch ( count )
			{
			case 0:
				CHECK(k == key_val2);
				CHECK(*v == val2);
				break;
			case 1:
				CHECK(k == key_val);
				CHECK(*v == val);
				break;
			default:
				break;
			}

		count++;
		}

	PDict<uint32_t>::iterator it;
	it = dict.begin();
	it = dict.end();
	PDict<uint32_t>::iterator it2 = it;

	CHECK(count == 2);

	delete key;
	delete key2;
	}

TEST_CASE("dict robust iteration")
	{
	PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	detail::HashKey* key = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	detail::HashKey* key2 = new detail::HashKey(key_val2);

	uint32_t val3 = 20;
	uint32_t key_val3 = 35;
	detail::HashKey* key3 = new detail::HashKey(key_val3);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	detail::HashKey* it_key;
	IterCookie* it = dict.InitForIteration();
	CHECK(it != nullptr);
	dict.MakeRobustCookie(it);

	int count = 0;

	while ( uint32_t* entry = dict.NextEntry(it_key, it) )
		{
		switch ( count )
			{
			case 0:
				CHECK(it_key->Hash() == (uint32_t)key2->Hash());
				CHECK(*entry == 10);
				dict.Insert(key3, &val3);
				break;
			case 1:
				CHECK(it_key->Hash() == (uint32_t)key->Hash());
				CHECK(*entry == 15);
				break;
			case 2:
				CHECK(it_key->Hash() == (uint32_t)key3->Hash());
				CHECK(*entry == 20);
				break;
			default:
				// We shouldn't get here.
				CHECK(false);
				break;
			}

		count++;
		delete it_key;
		}

	CHECK(count == 3);

	IterCookie* it2 = dict.InitForIteration();
	CHECK(it2 != nullptr);
 	dict.MakeRobustCookie(it2);

	count = 0;
	while ( uint32_t* entry = dict.NextEntry(it_key, it2) )
		{
		switch ( count )
			{
			case 0:
				CHECK(it_key->Hash() == (uint32_t)key2->Hash());
				CHECK(*entry == 10);
				dict.Remove(key3);
				break;
			case 1:
				CHECK(it_key->Hash() == (uint32_t)key->Hash());
				CHECK(*entry == 15);
				break;
			default:
				// We shouldn't get here.
				CHECK(false);
				break;
			}

		count++;
		delete it_key;
		}

	CHECK(count == 2);

#pragma GCC diagnostic pop

	delete key;
	delete key2;
	delete key3;
	}

TEST_CASE("dict new robust iteration")
	{
	PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	detail::HashKey* key = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	detail::HashKey* key2 = new detail::HashKey(key_val2);

	uint32_t val3 = 20;
	uint32_t key_val3 = 35;
	detail::HashKey* key3 = new detail::HashKey(key_val3);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

	{
	int count = 0;
	auto it = dict.begin_robust();

	for ( ; it != dict.end_robust(); ++it )
		{
		auto* v = it->GetValue<uint32_t*>();
		uint64_t k = *(uint32_t*) it->GetKey();

		switch ( count )
			{
			case 0:
				CHECK(k == key_val2);
				CHECK(*v == val2);
				dict.Insert(key3, &val3);
				break;
			case 1:
				CHECK(k == key_val);
				CHECK(*v == val);
				break;
			case 2:
				CHECK(k == key_val3);
				CHECK(*v == val3);
				break;
			default:
				// We shouldn't get here.
				CHECK(false);
				break;
			}
		count++;
		}

	CHECK(count == 3);
	}

	{
	int count = 0;
	auto it = dict.begin_robust();

	for ( ; it != dict.end_robust(); ++it )
		{
		auto* v = it->GetValue<uint32_t*>();
		uint64_t k = *(uint32_t*) it->GetKey();

		switch ( count )
			{
			case 0:
				CHECK(k == key_val2);
				CHECK(*v == val2);
				dict.Insert(key3, &val3);
				dict.Remove(key3);
				break;
			case 1:
				CHECK(k == key_val);
				CHECK(*v == val);
				break;
			default:
				// We shouldn't get here.
				CHECK(false);
				break;
			}
		count++;
		}

	CHECK(count == 2);
	}

	delete key;
	delete key2;
	delete key3;
	}

class DictTestDummy
	{
public:
	DictTestDummy(int v) : v(v) {}
	~DictTestDummy() {}
	int v = 0;
	};

TEST_CASE("dict robust iteration replacement")
	{
	PDict<DictTestDummy> dict;

	DictTestDummy* val1 = new DictTestDummy(15);
	uint32_t key_val1 = 5;
	detail::HashKey* key1 = new detail::HashKey(key_val1);

	DictTestDummy* val2 = new DictTestDummy(10);
	uint32_t key_val2 = 25;
	detail::HashKey* key2 = new detail::HashKey(key_val2);

	DictTestDummy* val3 = new DictTestDummy(20);
	uint32_t key_val3 = 35;
	detail::HashKey* key3 = new detail::HashKey(key_val3);

	dict.Insert(key1, val1);
	dict.Insert(key2, val2);
	dict.Insert(key3, val3);

	int count = 0;
	auto it = dict.begin_robust();

	// Iterate past the first couple of elements so we're not done, but the
	// iterator is still pointing at a valid element.
	for ( ; count != 2 && it != dict.end_robust(); ++count, ++it )
		{
		}

	// Store off the value at this iterator index
	auto* v = it->GetValue<DictTestDummy*>();

	// Replace it with something else
	auto k = it->GetHashKey();
	DictTestDummy* val4 = new DictTestDummy(50);
	dict.Insert(k.get(), val4);

	// Delete the original element
	delete val2;

	// This shouldn't crash with AddressSanitizer
	for ( ; it != dict.end_robust(); ++it )
		{
		uint64_t k = *(uint32_t*) it->GetKey();
		auto* v = it->GetValue<DictTestDummy*>();
		CHECK(v->v == 50);
		}

	delete key1;
	delete key2;
	delete key3;

	delete val1;
	delete val3;
	delete val4;
	}

TEST_CASE("dict iterator invalidation")
	{
	PDict<uint32_t> dict;

	uint32_t val = 15;
	uint32_t key_val = 5;
	auto key = new detail::HashKey(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	auto key2 = new detail::HashKey(key_val2);

	uint32_t val3 = 42;
	uint32_t key_val3 = 37;
	auto key3 = new detail::HashKey(key_val3);

	dict.Insert(key, &val);
	dict.Insert(key2, &val2);

	detail::HashKey* it_key;
	bool iterators_invalidated = false;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	IterCookie* it = dict.InitForIteration();
	CHECK(it != nullptr);

	while ( uint32_t* entry = dict.NextEntry(it_key, it) )
		{
		iterators_invalidated = false;
		dict.Remove(key3, &iterators_invalidated);
		// Key doesn't exist, nothing to remove, iteration not invalidated.
		CHECK(!iterators_invalidated);

		iterators_invalidated = false;
		dict.Insert(key, &val2, &iterators_invalidated);
		// Key exists, value gets overwritten, iteration not invalidated.
		CHECK(!iterators_invalidated);

		iterators_invalidated = false;
		dict.Remove(key2, &iterators_invalidated);
		// Key exists, gets removed, iteration is invalidated.
		CHECK(iterators_invalidated);

		delete it_key;
		dict.StopIteration(it);
		break;
		}

	it = dict.InitForIteration();
	CHECK(it != nullptr);

	while ( uint32_t* entry = dict.NextEntry(it_key, it) )
		{
		iterators_invalidated = false;
		dict.Insert(key3, &val3, &iterators_invalidated);
		// Key doesn't exist, gets inserted, iteration is invalidated.
		CHECK(iterators_invalidated);

		delete it_key;
		dict.StopIteration(it);
		break;
		}
#pragma GCC diagnostic pop

	CHECK(dict.Length() == 2);
	CHECK(*static_cast<uint32_t*>(dict.Lookup(key)) == val2);
	CHECK(*static_cast<uint32_t*>(dict.Lookup(key3)) == val3);
	CHECK(static_cast<uint32_t*>(dict.Lookup(key2)) == nullptr);

	delete key;
	delete key2;
	delete key3;
	}

TEST_SUITE_END();

/////////////////////////////////////////////////////////////////////////////////////////////////
//bucket math
int Dictionary::Log2(int num) const
	{
	int i = 0;
	while ( num >>= 1 )
		i++;
	return i;
	}

int Dictionary::Buckets(bool expected) const
	{
	int buckets = ( 1 << log2_buckets );
	if ( expected )
		return buckets;
	return table ? buckets : 0;
	}

int Dictionary::Capacity(bool expected) const
	{
	int capacity = ( 1 << log2_buckets ) + ( log2_buckets+0 );
	if ( expected )
		return capacity;
	return table ? capacity : 0;
	}

int Dictionary::ThresholdEntries() const
	{
	// Increase the size of the dictionary when it is 75% full. However, when the dictionary
	// is small ( <= 20 elements ), only resize it when it's 100% full. The dictionary will
	// always resize when the current insertion causes it to be full. This ensures that the
	// current insertion should always be successful.
	int capacity = Capacity();
	if ( log2_buckets <= detail::DICT_THRESHOLD_BITS )
		return capacity; //20 or less elements, 1.0, only size up when necessary.
	return capacity - ( capacity >> detail::DICT_LOAD_FACTOR_BITS );
	}

detail::hash_t Dictionary::FibHash(detail::hash_t h) const
	{
	//GoldenRatio phi = (sqrt(5)+1)/2 = 1.6180339887...
	//1/phi = phi - 1
	h &= detail::HASH_MASK;
	h *= 11400714819323198485llu; //2^64/phi
	return h;
	}

// return position in dict with 2^bit size.
int Dictionary::BucketByHash(detail::hash_t h, int log2_table_size) const //map h to n-bit
	{
	ASSERT(log2_table_size>=0);
	if ( ! log2_table_size )
		return 0; //<< >> breaks on  64.

#ifdef DICT_NO_FIB_HASH
	detail::hash_t hash = h;
#else
	detail::hash_t hash = FibHash(h);
#endif

	int m = 64 - log2_table_size;
	hash <<= m;
	hash >>= m;

	return hash;
	}

//given entry at index i, return it's perfect bucket position.
int Dictionary::BucketByPosition(int position) const
	{
	ASSERT(table && position>=0 && position < Capacity() && ! table[position].Empty());
	return position - table[position].distance;
	}

////////////////////////////////////////////////////////////////////////////////////////////////
//Cluster Math
////////////////////////////////////////////////////////////////////////////////////////////////

int Dictionary::EndOfClusterByBucket(int bucket) const
	{
	ASSERT(bucket>=0 && bucket < Buckets());
	int i = bucket;
	while ( i < Capacity() && ! table[i].Empty() && BucketByPosition(i) <= bucket )
		i++;
	return i;
	}

int Dictionary::HeadOfClusterByPosition( int position) const
	{
	// Finding the first entry in the bucket chain.
	ASSERT(0 <= position && position < Capacity() && ! table[position].Empty());

	// Look backward for the first item with the same bucket as myself.
	int bucket = BucketByPosition(position);
	int i = position;
	while ( i >= bucket && BucketByPosition(i) == bucket )
		i--;

	return i == bucket ? i : i + 1;
	}

int Dictionary::TailOfClusterByPosition(int position) const
	{
	ASSERT(0 <= position && position < Capacity() && ! table[position].Empty());

	int bucket = BucketByPosition(position);
	int i = position;
	while ( i < Capacity() && ! table[i].Empty() && BucketByPosition(i) == bucket )
		i++; //stop just over the tail.

	return i - 1;
	}

int Dictionary::EndOfClusterByPosition(int position) const
	{
	return TailOfClusterByPosition(position)+1;
	}

int Dictionary::OffsetInClusterByPosition(int position) const
	{
	ASSERT(0 <= position && position < Capacity() && ! table[position].Empty());
	int head = HeadOfClusterByPosition(position);
	return position - head;
	}

// Find the next valid entry after the position. Position can be -1, which means
// look for the next valid entry point altogether.
int Dictionary::Next(int position) const
	{
	ASSERT(table && -1 <= position && position < Capacity());

	do
		{
		position++;
		} while ( position < Capacity() && table[position].Empty() );

	return position;
	}

///////////////////////////////////////////////////////////////////////////////////////////////////////
//Debugging
///////////////////////////////////////////////////////////////////////////////////////////////////////
#define DUMPIF(f) if(f) Dump(1)
#ifdef DEBUG
void Dictionary::AssertValid() const
	{
	bool valid = true;
	int n = num_entries;

	if ( table )
		for ( int i = Capacity()-1; i >= 0; i-- )
			if ( ! table[i].Empty() )
				n--;

	valid = (n == 0);
	ASSERT(valid);
	DUMPIF(! valid);

	//entries must clustered together
	for ( int i = 1; i < Capacity(); i++ )
		{
		if ( ! table || table[i].Empty() )
			continue;

		if ( table[i-1].Empty() )
			{
			valid = (table[i].distance == 0);
			ASSERT(valid);
			DUMPIF(! valid);
			}
		else
			{
			valid = (table[i].bucket >= table[i-1].bucket);
			ASSERT(valid);
			DUMPIF(! valid);

			if ( table[i].bucket == table[i-1].bucket )
				{
				valid = (table[i].distance == table[i-1].distance+1);
				ASSERT(valid);
				DUMPIF(! valid);
				}
			else
				{
				valid = (table[i].distance <= table[i-1].distance);
				ASSERT(valid);
				DUMPIF(! valid);
				}
			}
		}
	}
#endif//DEBUG

size_t Dictionary::MemoryAllocation() const
	{
	size_t size = padded_sizeof(*this);
	if ( table )
		{
		size += zeek::util::pad_size(Capacity() * sizeof(detail::DictEntry));
		for ( int i = Capacity()-1; i>=0; i-- )
			if ( ! table[i].Empty() && table[i].key_size > 8 )
				size += zeek::util::pad_size(table[i].key_size);
		}

	if ( order )
		size += padded_sizeof(std::vector<detail::DictEntry>) + zeek::util::pad_size(sizeof(detail::DictEntry) * order->capacity());

	return size;
	}

void Dictionary::DumpKeys() const
	{
	if ( ! table )
		return;

	char key_file[100];
	// Detect string or binary from first key.
	int i=0;
	while ( table[i].Empty() && i < Capacity() )
		i++;

	bool binary = false;
	const char* key = table[i].GetKey();
	for ( int j = 0; j < table[i].key_size; j++ )
		if ( ! isprint(key[j]) )
			{
			binary = true;
			break;
			}
	int max_distance = 0;

	DistanceStats(max_distance);
	if ( binary )
		{
		char key = char(random() % 26) + 'A';
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		sprintf(key_file, "%d.%d.%zu-%c.key", Length(), max_distance, MemoryAllocation()/Length(), key);
#pragma GCC diagnostic pop
		std::ofstream f(key_file, std::ios::binary|std::ios::out|std::ios::trunc);
		for ( int idx = 0; idx < Capacity(); idx++ )
			if ( ! table[idx].Empty() )
				{
				int key_size = table[idx].key_size;
				f.write((const char*)&key_size, sizeof(int));
				f.write(table[idx].GetKey(), table[idx].key_size);
				}
		}
	else
		{
		char key = char(random() % 26) + 'A';
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
		sprintf(key_file, "%d.%d.%zu-%d.ckey",Length(), max_distance, MemoryAllocation()/Length(), key);
#pragma GCC diagnostic pop
		std::ofstream f(key_file, std::ios::out|std::ios::trunc);
		for ( int idx = 0; idx < Capacity(); idx++ )
			if ( ! table[idx].Empty() )
				{
				std::string s((char*)table[idx].GetKey(), table[idx].key_size);
				f << s << std::endl;
				}
		}
	}

void Dictionary::DistanceStats(int& max_distance, int* distances, int num_distances) const
	{
	max_distance = 0;
	for ( int i = 0; i < num_distances; i++ )
		distances[i] = 0;

	for ( int i = 0; i < Capacity(); i++ )
		{
		if ( table[i].Empty() )
			continue;
		if ( table[i].distance > max_distance )
			max_distance = table[i].distance;
		if ( num_distances <= 0 || ! distances )
			continue;
		if ( table[i].distance >= num_distances-1 )
			distances[num_distances-1]++;
		else
			distances[table[i].distance]++;
		}
	}

void Dictionary::Dump(int level) const
	{
	int key_size = 0;
	for ( int i = 0; i < Capacity(); i++ )
		{
		if ( table[i].Empty() )
			continue;
		key_size += zeek::util::pad_size(table[i].key_size);
		if ( ! table[i].value )
			continue;
		}

#define DICT_NUM_DISTANCES 5
	int distances[DICT_NUM_DISTANCES];
	int max_distance = 0;
	DistanceStats(max_distance, distances, DICT_NUM_DISTANCES);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
	printf("cap %'7d ent %'7d %'-7d load %.2f max_dist %2d mem %10zu mem/ent %3zu key/ent %3d lg %2d remaps %1d remap_end %4d ",
		Capacity(), Length(), MaxLength(), (double)Length()/(table? Capacity() : 1),
		max_distance, MemoryAllocation(), (MemoryAllocation())/(Length()?Length():1), key_size / (Length()?Length():1),
		log2_buckets, remaps, remap_end);
#pragma GCC diagnostic pop
	if ( Length() > 0 )
		{
		for (int i = 0; i < DICT_NUM_DISTANCES-1; i++)
			printf("[%d]%2d%% ", i, 100*distances[i]/Length());
		printf("[%d+]%2d%% ", DICT_NUM_DISTANCES-1, 100*distances[DICT_NUM_DISTANCES-1]/Length());
		}
	else
		printf("\n");

	printf("\n");
	if ( level >= 1 )
		{
		printf("%-10s %1s %-10s %-4s %-4s %-10s %-18s %-2s\n", "Index", "*","Bucket", "Dist", "Off", "Hash", "FibHash", "KeySize");
		for ( int i = 0; i < Capacity(); i++ )
			if ( table[i].Empty() )
				printf("%'10d \n", i);
			else
				printf("%'10d %1s %'10d %4d %4d 0x%08x 0x%016" PRIx64 "(%3d) %2d\n",
					i, (i<=remap_end? "*":  ""), BucketByPosition(i), (int)table[i].distance, OffsetInClusterByPosition(i),
					uint(table[i].hash), FibHash(table[i].hash), (int)FibHash(table[i].hash)&0xFF, (int)table[i].key_size);
		}
	}

////////////////////////////////////////////////////////////////////////////////////////////////////
//Initialization.
////////////////////////////////////////////////////////////////////////////////////////////////////
Dictionary::Dictionary(DictOrder ordering, int initial_size)
	{
	if ( initial_size > 0 )
		{
		// If an initial size is speicified, init the table right away. Otherwise wait until the
		// first insertion to init.
		log2_buckets = Log2(initial_size);
		Init();
		}

	if ( ordering == ORDERED )
		order = new std::vector<detail::DictEntry>;
	}

Dictionary::~Dictionary()
	{
	Clear();
	}

void Dictionary::Clear()
	{
	if ( table )
		{
		for ( int i = Capacity() - 1; i >= 0; i-- )
			{
			if ( table[i].Empty() )
				continue;
			if ( delete_func )
				delete_func(table[i].value);
			table[i].Clear();
			}
		free(table);
		table = nullptr;
		}

	if ( order )
		{
		delete order;
		order = nullptr;
		}
	if ( cookies )
		{
		delete cookies;
		cookies = nullptr;
		}
	if ( iterators )
		{
		delete iterators;
		iterators = nullptr;
		}
	log2_buckets = 0;
	num_iterators = 0;
	remaps = 0;
	remap_end = -1;
	num_entries = 0;
	max_entries = 0;
	}

void Dictionary::Init()
	{
	ASSERT(! table);
	table = (detail::DictEntry*)malloc(sizeof(detail::DictEntry) * Capacity(true));
	for ( int i = Capacity() - 1; i >= 0; i-- )
		table[i].SetEmpty();
	}

// private
void generic_delete_func(void* v)
	{
	free(v);
	}

//////////////////////////////////////////////////////////////////////////////////////////
//Lookup

// Look up now also possibly modifies the entry. Why? if the entry is found but not positioned
// according to the current dict (so it's before SizeUp), it will be moved to the right
// position so next lookup is fast.
void* Dictionary::Lookup(const detail::HashKey* key) const
	{
	return Lookup(key->Key(), key->Size(), key->Hash());
	}

void* Dictionary::Lookup(const void* key, int key_size, detail::hash_t h) const
	{
	Dictionary* d = const_cast<Dictionary*>(this);
	int position = d->LookupIndex(key, key_size, h);
	return position >= 0 ? table[position].value : nullptr;
	}

//for verification purposes
int Dictionary::LinearLookupIndex(const void* key, int key_size, detail::hash_t hash) const
	{
	for ( int i = 0; i < Capacity(); i++ )
		if ( ! table[i].Empty() && table[i].Equal((const char*)key, key_size, hash) )
			return i;
	return -1;
	}

// Lookup position for all possible table_sizes caused by remapping. Remap it immediately
// if not in the middle of iteration.
int Dictionary::LookupIndex(const void* key, int key_size, detail::hash_t hash, int* insert_position, int* insert_distance)
	{
	ASSERT_VALID(this);
	if ( ! table )
		return -1;

	int bucket = BucketByHash(hash, log2_buckets);
#ifdef DEBUG
	int linear_position = LinearLookupIndex(key, key_size, hash);
#endif//DEBUG
	int position = LookupIndex(key, key_size, hash, bucket, Capacity(), insert_position, insert_distance);
	if ( position >= 0 )
		{
		ASSERT(position == linear_position);//same as linearLookup
		return position;
		}

	for ( int i = 1; i <= remaps; i++ )
		{
		int prev_bucket = BucketByHash(hash,log2_buckets - i);
		if ( prev_bucket <= remap_end )
			{
			// possibly here. insert_position & insert_distance returned on failed lookup is
			// not valid in previous table_sizes.
			position = LookupIndex(key, key_size, hash, prev_bucket, remap_end+1);
			if ( position >= 0 )
				{
				ASSERT(position == linear_position);//same as linearLookup
				//remap immediately if no iteration is on.
				if ( ! num_iterators )
					{
					Remap(position, &position);
					ASSERT(position == LookupIndex(key, key_size, hash));
					}
				return position;
				}
			}
		}
	//not found
#ifdef DEBUG
	if ( linear_position >= 0 )
		{//different. stop and try to see whats happending.
		ASSERT(false);
		//rerun the function in debugger to track down the bug.
		LookupIndex(key, key_size, hash);
		}
#endif//DEBUG
	return -1;
	}

// Returns the position of the item if it exists. Otherwise returns -1, but set the insert
// position/distance if required. The starting point for the search may not be the bucket
// for the current table size since this method is also used to search for an item in the
// previous table size.
int Dictionary::LookupIndex(const void* key, int key_size, detail::hash_t hash, int bucket, int end,
                            int* insert_position/*output*/, int* insert_distance/*output*/)
	{
	ASSERT(bucket>=0 && bucket < Buckets());
	int i = bucket;
	for ( ; i < end && ! table[i].Empty() && BucketByPosition(i) <= bucket; i++ )
		if ( BucketByPosition(i) == bucket && table[i].Equal((char*)key, key_size, hash) )
			return i;

	//no such cluster, or not found in the cluster.
	if ( insert_position )
		*insert_position = i;

	if ( insert_distance )
		{
		*insert_distance = i - bucket;

		if ( *insert_distance >= detail::TOO_FAR_TO_REACH )
			reporter->FatalErrorWithCore("Dictionary (size %d) insertion distance too far: %d",
			                             Length(), *insert_distance);
		}

	return -1;
	}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Insert
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void* Dictionary::Insert(void* key, int key_size, detail::hash_t hash, void* val, bool copy_key, bool* iterators_invalidated)
	{
	ASSERT_VALID(this);

	// Initialize the table if it hasn't been done yet. This saves memory storing a bunch
	// of empty dicts.
	if ( ! table )
		Init();

	void* v = nullptr;

	// Look to see if this key is already in the table. If found, insert_position is the
	// position of the existing element. If not, insert_position is where it'll be inserted
	// and insert_distance is the distance of the key for the position.
	int insert_position = -1, insert_distance = -1;
	int position = LookupIndex(key, key_size, hash, &insert_position, &insert_distance);
	if ( position >= 0 )
		{
		v = table[position].value;
		table[position].value = val;
		if ( ! copy_key )
			delete [] (char*)key;

		if ( order )
			{//set new v to order too.
			auto it = std::find(order->begin(), order->end(), table[position]);
			ASSERT(it != order->end());
			it->value = val;
			}

		if ( cookies && ! cookies->empty() )
			//need to set new v for cookies too.
			for ( auto c: *cookies )
				{
				ASSERT_VALID(c);
				//ASSERT(false);
				auto it = std::find(c->inserted->begin(), c->inserted->end(), table[position]);
				if ( it != c->inserted->end() )
					it->value = val;
				}

		if ( iterators && ! iterators->empty() )
			//need to set new v for iterators too.
			for ( auto c: *iterators )
				{
				// Check to see if this iterator points at the entry we're replacing. The iterator
				// keeps a copy of the element, so we need to update it too.
				if ( **c == table[position] )
					(*c)->value = val;

				// Check if any of the inserted elements in this iterator point at the entry being
				// replaced. Update those too.
				auto it = std::find(c->inserted->begin(), c->inserted->end(), table[position]);
				if ( it != c->inserted->end() )
					it->value = val;
				}
		}
	else
		{
		if ( ! HaveOnlyRobustIterators() )
			{
			if ( iterators_invalidated )
				*iterators_invalidated = true;
			else
				reporter->InternalWarning("Dictionary::Insert() possibly caused iterator invalidation");
			}

		// Allocate memory for key if necesary. Key is updated to reflect internal key if necessary.
		detail::DictEntry entry(key, key_size, hash, val, insert_distance, copy_key);
		InsertRelocateAndAdjust(entry, insert_position);
		if ( order )
			order->push_back(entry);

		num_entries++;
		cum_entries++;
		if ( max_entries < num_entries )
			max_entries = num_entries;
		if ( num_entries > ThresholdEntries() )
			SizeUp();
		}

	// Remap after insert can adjust asap to shorten period of mixed table.
	// TODO: however, if remap happens right after size up, then it consumes more cpu for this cycle,
	// a possible hiccup point.
	if ( Remapping() )
		Remap();
	ASSERT_VALID(this);
	return v;
	}

///e.distance is adjusted to be the one at insert_position.
void Dictionary::InsertRelocateAndAdjust(detail::DictEntry& entry, int insert_position)
	{
#ifdef DEBUG
	entry.bucket = BucketByHash(entry.hash,log2_buckets);
#endif//DEBUG
	int last_affected_position = insert_position;
	InsertAndRelocate(entry, insert_position, &last_affected_position);

	// If remapping in progress, adjust the remap_end to step back a little to cover the new
	// range if the changed range straddles over remap_end.
	if ( Remapping() && insert_position <= remap_end && remap_end < last_affected_position )
		{//[i,j] range changed. if map_end in between. then possibly old entry pushed down across map_end.
		remap_end = last_affected_position; //adjust to j on the conservative side.
		}

	if ( cookies && ! cookies->empty() )
		for ( auto c: *cookies )
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
			AdjustOnInsert(c, entry, insert_position, last_affected_position);
#pragma GCC diagnostic pop
	if ( iterators && ! iterators->empty() )
		for ( auto c: *iterators )
			AdjustOnInsert(c, entry, insert_position, last_affected_position);
	}

/// insert entry into position, relocate other entries when necessary.
void Dictionary::InsertAndRelocate(detail::DictEntry& entry, int insert_position, int* last_affected_position)
	{///take out the head of cluster and append to the end of the cluster.
	while ( true )
		{
		if ( insert_position >= Capacity() )
			{
			ASSERT(insert_position == Capacity());
			SizeUp(); //copied all the items to new table. as it's just copying without remapping, insert_position is now empty.
			table[insert_position] = entry;
			if ( last_affected_position )
				*last_affected_position = insert_position;
			return;
			}
		if ( table[insert_position].Empty() )
			{   //the condition to end the loop.
			table[insert_position] = entry;
			if ( last_affected_position )
				*last_affected_position = insert_position;
			return;
			}

		//the to-be-swapped-out item appends to the end of its original cluster.
		auto t = table[insert_position];
		int next = EndOfClusterByPosition(insert_position);
		t.distance += next - insert_position;

		//swap
		table[insert_position] = entry;
		entry = t;
		insert_position = next; //append to the end of the current cluster.
		}
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/// Adjust Cookies on Insert.
void Dictionary::AdjustOnInsert(IterCookie* c, const detail::DictEntry& entry, int insert_position, int last_affected_position)
	{
	ASSERT(c);
	ASSERT_VALID(c);
	if ( insert_position < c->next )
		c->inserted->push_back(entry);
	if ( insert_position < c->next && c->next <= last_affected_position )
		{
		int k = TailOfClusterByPosition(c->next);
		ASSERT(k >= 0 && k < Capacity());
		c->visited->push_back(table[k]);
		}
	}

#pragma GCC diagnostic pop

void Dictionary::AdjustOnInsert(RobustDictIterator* c, const detail::DictEntry& entry,
                                int insert_position, int last_affected_position)
	{
	if ( insert_position < c->next )
		c->inserted->push_back(entry);
	if ( insert_position < c->next && c->next <= last_affected_position )
		{
		int k = TailOfClusterByPosition(c->next);
		ASSERT(k >= 0 && k < Capacity());
		c->visited->push_back(table[k]);
		}
	}

void Dictionary::SizeUp()
	{
	int prev_capacity = Capacity();
	log2_buckets++;
	int capacity = Capacity();
	table = (detail::DictEntry*)realloc(table, capacity * sizeof(detail::DictEntry));
	for ( int i = prev_capacity; i < capacity; i++ )
		table[i].SetEmpty();

	// REmap from last to first in reverse order. SizeUp can be triggered by 2 conditions, one of
	// which is that the last space in the table is occupied and there's nowhere to put new items.
	// In this case, the table doubles in capacity and the item is put at the prev_capacity
	// position with the old hash. We need to cover this item (?).
	remap_end = prev_capacity; //prev_capacity instead of prev_capacity-1.

	//another remap starts.
	remaps++; //used in Lookup() to cover SizeUp with incomplete remaps.
	ASSERT(remaps <= log2_buckets);//because we only sizeUp, one direction. we know the previous log2_buckets.
	}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Remove
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void* Dictionary::Remove(const void* key, int key_size, detail::hash_t hash, bool dont_delete, bool* iterators_invalidated)
	{//cookie adjustment: maintain inserts here. maintain next in lower level version.
	ASSERT_VALID(this);

	ASSERT(! dont_delete); //this is a poorly designed flag. if on, the internal has nowhere to return and memory is lost.

	int position = LookupIndex(key, key_size, hash);
	if ( position < 0 )
		return nullptr;

	if ( ! HaveOnlyRobustIterators() )
		{
		if ( iterators_invalidated )
			*iterators_invalidated = true;
		else
			reporter->InternalWarning("Dictionary::Remove() possibly caused iterator invalidation");
		}

	detail::DictEntry entry = RemoveRelocateAndAdjust(position);
	num_entries--;
	ASSERT(num_entries >= 0);
	//e is about to be invalid. remove it from all references.
	if ( order )
		order->erase(std::remove(order->begin(), order->end(), entry), order->end());

	void* v = entry.value;
	entry.Clear();
	ASSERT_VALID(this);
	return v;
	}

detail::DictEntry Dictionary::RemoveRelocateAndAdjust(int position)
	{
	int last_affected_position = position;
	detail::DictEntry entry = RemoveAndRelocate(position, &last_affected_position);

#ifdef DEBUG
	//validation: index to i-1 should be continuous without empty spaces.
	for ( int k = position; k < last_affected_position; k++ )
		ASSERT(! table[k].Empty());
#endif//DEBUG

	if ( cookies && ! cookies->empty() )
		for ( auto c: *cookies )
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
			AdjustOnRemove(c, entry, position, last_affected_position);
#pragma GCC diagnostic pop

	if ( iterators && ! iterators->empty() )
		for ( auto c: *iterators )
			AdjustOnRemove(c, entry, position, last_affected_position);

	return entry;
	}

detail::DictEntry Dictionary::RemoveAndRelocate(int position, int* last_affected_position)
	{
	//fill the empty position with the tail of the cluster of position+1.
	ASSERT(position >= 0 && position < Capacity() && ! table[position].Empty());

	detail::DictEntry entry = table[position];
	while ( true )
		{
		if ( position == Capacity() - 1 || table[position+1].Empty() || table[position+1].distance == 0 )
			{
			//no next cluster to fill, or next position is empty or next position is already in perfect bucket.
			table[position].SetEmpty();
			if ( last_affected_position )
				*last_affected_position = position;
			return entry;
			}
		int next = TailOfClusterByPosition(position+1);
		table[position] = table[next];
		table[position].distance -= next - position; //distance improved for the item.
		position = next;
		}

	return entry;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

void Dictionary::AdjustOnRemove(IterCookie* c, const detail::DictEntry& entry, int position, int last_affected_position)
	{
	ASSERT_VALID(c);
	c->inserted->erase(std::remove(c->inserted->begin(), c->inserted->end(), entry), c->inserted->end());
	if ( position < c->next && c->next <= last_affected_position )
		{
		int moved = HeadOfClusterByPosition(c->next-1);
		if ( moved < position )
			moved = position;
		c->inserted->push_back(table[moved]);
		}

	//if not already the end of the dictionary, adjust next to a valid one.
	if ( c->next < Capacity() && table[c->next].Empty() )
		c->next = Next(c->next);
	}

#pragma GCC diagnostic pop

void Dictionary::AdjustOnRemove(RobustDictIterator* c, const detail::DictEntry& entry,
                                int position, int last_affected_position)
	{
	c->inserted->erase(std::remove(c->inserted->begin(), c->inserted->end(), entry), c->inserted->end());
	if ( position < c->next && c->next <= last_affected_position )
		{
		int moved = HeadOfClusterByPosition(c->next-1);
		if ( moved < position )
			moved = position;
		c->inserted->push_back(table[moved]);
		}

	//if not already the end of the dictionary, adjust next to a valid one.
	if ( c->next < Capacity() && table[c->next].Empty() )
		c->next = Next(c->next);
	}

///////////////////////////////////////////////////////////////////////////////////////////////////
//Remap
///////////////////////////////////////////////////////////////////////////////////////////////////

void Dictionary::Remap()
	{
	///since remap should be very fast. take more at a time.
	///delay Remap when cookie is there. hard to handle cookie iteration while size changes.
	///remap from bottom up.
	///remap creates two parts of the dict: [0,remap_end] (remap_end, ...]. the former is mixed with old/new entries; the latter contains all new entries.
	///
	if ( num_iterators > 0 )
		return;

	int left = detail::DICT_REMAP_ENTRIES;
	while ( remap_end >= 0 && left > 0 )
		{
		if ( ! table[remap_end].Empty() && Remap(remap_end) )
			left--;
		else//< successful Remap may increase remap_end in the case of SizeUp due to insert. if so, remap_end need to be worked on again.
			remap_end--;
		}
	if ( remap_end < 0 )
		remaps = 0; //done remapping.
	}

bool Dictionary::Remap(int position, int* new_position)
	{
	ASSERT_VALID(this);
	///Remap changes item positions by remove() and insert(). to avoid excessive operation. avoid it when safe iteration is in progress.
	ASSERT( ( ! cookies || cookies->empty() ) && ( ! iterators || iterators->empty() ) );
	int current = BucketByPosition(position);//current bucket
	int expected = BucketByHash(table[position].hash, log2_buckets); //expected bucket in new table.
	//equal because 1: it's a new item, 2: it's an old item, but new bucket is the same as old. 50% of old items act this way due to fibhash.
	if ( current == expected )
		return false;
	detail::DictEntry entry = RemoveAndRelocate(position); // no iteration cookies to adjust, no need for last_affected_position.
#ifdef DEBUG
	entry.bucket = expected;
#endif//DEBUG

	//find insert position.
	int insert_position = EndOfClusterByBucket(expected);
	if ( new_position )
		*new_position = insert_position;
	entry.distance = insert_position - expected;
	InsertAndRelocate(entry, insert_position);// no iteration cookies to adjust, no need for last_affected_position.
	ASSERT_VALID(this);
	return true;
	}

void* Dictionary::NthEntry(int n, const void*& key, int& key_size) const
	{
	if ( ! order || n < 0 || n >= Length() )
		return nullptr;
	detail::DictEntry entry = (*order)[n];
	key = entry.GetKey();
	key_size = entry.key_size;
	return entry.value;
	}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Iteration
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

void Dictionary::MakeRobustCookie(IterCookie* cookie)
	{ //make sure c->next >= 0.
	if ( ! cookies )
		cookies = new std::vector<IterCookie*>;
	cookie->MakeRobust();
	ASSERT_VALID(cookie);
	}

IterCookie* Dictionary::InitForIterationNonConst() //const
	{
	IncrIters();
	return new IterCookie(const_cast<Dictionary*>(this));
	}

void Dictionary::StopIterationNonConst(IterCookie* cookie) //const
	{
	ASSERT(num_iterators > 0);
	if ( num_iterators > 0 )
		DecrIters();
	delete cookie;
	}

void* Dictionary::NextEntryNonConst(detail::HashKey*& h, IterCookie*& c, bool return_hash) //const
	{
	// If there are any inserted entries, return them first.
	// That keeps the list small and helps avoiding searching
	// a large list when deleting an entry.
	ASSERT(c);
	ASSERT_VALID(c);
	if ( ! table )
		{
		if ( num_iterators > 0 )
			DecrIters();
		delete c;
		c = nullptr;
		return nullptr; //end of iteration.
		}

	if ( c->inserted && ! c->inserted->empty() )
		{
		// Return the last one. Order doesn't matter,
		// and removing from the tail is cheaper.
		detail::DictEntry e = c->inserted->back();
		if ( return_hash )
			h = new detail::HashKey(e.GetKey(), e.key_size, e.hash);
		void* v = e.value;
		c->inserted->pop_back();
		return v;
		}

	if ( c->next < 0 )
		c->next = Next(-1);

	ASSERT(c->next >= Capacity() || ! table[c->next].Empty());

	//filter out visited keys.
	int capacity = Capacity();
	if ( c->visited && ! c->visited->empty() )
		//filter out visited entries.
		while ( c->next < capacity )
			{
			ASSERT(! table[c->next].Empty());
			auto it = std::find(c->visited->begin(), c->visited->end(), table[c->next]);
			if ( it == c->visited->end() )
				break;
			c->visited->erase(it);
			c->next = Next(c->next);
			}

	if ( c->next >= capacity )
		{//end.
		if ( num_iterators > 0 )
			DecrIters();
		delete c;
		c = nullptr;
		return nullptr; //end of iteration.
		}

	ASSERT(! table[c->next].Empty());
	void* v = table[c->next].value;
	if ( return_hash )
		h = new detail::HashKey(table[c->next].GetKey(), table[c->next].key_size, table[c->next].hash);

	//prepare for next time.
	c->next = Next(c->next);
	ASSERT_VALID(c);
	return v;
	}

IterCookie* Dictionary::InitForIteration() const
	{
	Dictionary* dp = const_cast<Dictionary*>(this);
	return dp->InitForIterationNonConst();
	}

void* Dictionary::NextEntry(detail::HashKey*& h, IterCookie*& cookie, bool return_hash) const
	{
	Dictionary* dp = const_cast<Dictionary*>(this);
	return dp->NextEntryNonConst(h, cookie, return_hash);
	}

void Dictionary::StopIteration(IterCookie* cookie) const
	{
	Dictionary* dp = const_cast<Dictionary*>(this);
	dp->StopIterationNonConst(cookie);
	}

#pragma GCC diagnostic pop

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// New Iteration
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////

DictIterator::DictIterator(const Dictionary* d, detail::DictEntry* begin, detail::DictEntry* end)
	: curr(begin), end(end)
	{
	// Make sure that we're starting on a non-empty element.
	while ( curr != end && curr->Empty() )
		++curr;

	// Cast away the constness so that the number of iterators can be modified in the dictionary. This does
	// violate the constness guarantees of const-begin()/end() and cbegin()/cend(), but we're not modifying the
	// actual data in the collection, just a counter in the wrapper of the collection.
	dict = const_cast<Dictionary*>(d);
	dict->IncrIters();
	}

DictIterator::~DictIterator()
	{
	if ( dict )
		{
		assert(dict->num_iterators > 0);
		dict->DecrIters();
		}
	}

DictIterator& DictIterator::operator++()
	{
	// The non-robust case is easy. Just advanced the current position forward until you find
	// one isn't empty and isn't the end.
	do {
		++curr;
		}
	while ( curr != end && curr->Empty() );

	return *this;
	}

DictIterator::DictIterator(const DictIterator& that)
	{
	if ( this == &that )
		return;

	if ( dict )
		{
		assert(dict->num_iterators > 0);
		dict->DecrIters();
		}

	dict = that.dict;
	curr = that.curr;
	end = that.end;
	dict->IncrIters();
	}

DictIterator& DictIterator::operator=(const DictIterator& that)
	{
	if ( this == &that )
		return *this;

	if ( dict )
		{
		assert(dict->num_iterators > 0);
		dict->DecrIters();
		}

	dict = that.dict;
	curr = that.curr;
	end = that.end;
	dict->IncrIters();

	return *this;
	}

DictIterator::DictIterator(DictIterator&& that)
	{
	if ( this == &that )
		return;

	if ( dict )
		{
		assert(dict->num_iterators > 0);
		dict->DecrIters();
		}

	dict = that.dict;
	curr = that.curr;
	end = that.end;

	that.dict = nullptr;
	}

DictIterator& DictIterator::operator=(DictIterator&& that)
	{
	if ( this == &that )
		return *this;

	if ( dict )
		{
		assert(dict->num_iterators > 0);
		dict->DecrIters();
		}

	dict = that.dict;
	curr = that.curr;
	end = that.end;

	that.dict = nullptr;

	return *this;
	}




RobustDictIterator Dictionary::MakeRobustIterator()
	{
	if ( ! iterators )
		iterators = new std::vector<RobustDictIterator*>;

	return { this };
	}

detail::DictEntry Dictionary::GetNextRobustIteration(RobustDictIterator* iter)
	{
	// If there are any inserted entries, return them first.
	// That keeps the list small and helps avoiding searching
	// a large list when deleting an entry.
	if ( ! table )
		{
		iter->Complete();
		return detail::DictEntry(nullptr); // end of iteration
		}

	if ( iter->inserted && ! iter->inserted->empty() )
		{
		// Return the last one. Order doesn't matter,
		// and removing from the tail is cheaper.
		detail::DictEntry e = iter->inserted->back();
		iter->inserted->pop_back();
		return e;
		}

	if ( iter->next < 0 )
		iter->next = Next(-1);

	ASSERT(iter->next >= Capacity() || ! table[iter->next].Empty());

	// Filter out visited keys.
	int capacity = Capacity();
	if ( iter->visited && ! iter->visited->empty() )
		// Filter out visited entries.
		while ( iter->next < capacity )
			{
			ASSERT(! table[iter->next].Empty());
			auto it = std::find(iter->visited->begin(), iter->visited->end(), table[iter->next]);
			if ( it == iter->visited->end() )
				break;
			iter->visited->erase(it);
			iter->next = Next(iter->next);
			}

	if ( iter->next >= capacity )
		{
		iter->Complete();
		return detail::DictEntry(nullptr); // end of iteration
		}

	ASSERT(! table[iter->next].Empty());
	detail::DictEntry e = table[iter->next];

	//prepare for next time.
	iter->next = Next(iter->next);
	return e;
	}

RobustDictIterator::RobustDictIterator(Dictionary* d) : curr(nullptr), dict(d)
	{
	next = -1;
	inserted = new std::vector<detail::DictEntry>();
	visited = new std::vector<detail::DictEntry>();

	dict->IncrIters();
	dict->iterators->push_back(this);

	// Advance the iterator one step so that we're at the first element.
	curr = dict->GetNextRobustIteration(this);
	}

RobustDictIterator::RobustDictIterator(const RobustDictIterator& other) : curr(nullptr)
	{
	dict = nullptr;

	if ( other.dict )
		{
		next = other.next;
		inserted = new std::vector<detail::DictEntry>();
		visited = new std::vector<detail::DictEntry>();

		if ( other.inserted )
			std::copy(other.inserted->begin(), other.inserted->end(), std::back_inserter(*inserted));

		if ( other.visited)
			std::copy(other.visited->begin(), other.visited->end(), std::back_inserter(*visited));

		dict = other.dict;
		dict->IncrIters();
		dict->iterators->push_back(this);

		curr = other.curr;
		}
	}

RobustDictIterator::RobustDictIterator(RobustDictIterator&& other) : curr(nullptr)
	{
	dict = nullptr;

	if ( other.dict )
		{
		next = other.next;
		inserted = other.inserted;
		visited = other.visited;

		dict = other.dict;
		dict->iterators->push_back(this);
		dict->iterators->erase(std::remove(dict->iterators->begin(), dict->iterators->end(), &other),
		                       dict->iterators->end());
		other.dict = nullptr;

		curr = std::move(other.curr);
		}
	}

RobustDictIterator::~RobustDictIterator()
	{
	Complete();
	}

void RobustDictIterator::Complete()
	{
	if ( dict )
		{
		assert(dict->num_iterators > 0);
		dict->DecrIters();

		dict->iterators->erase(std::remove(dict->iterators->begin(), dict->iterators->end(), this),
		                       dict->iterators->end());

		delete inserted;
		delete visited;

		inserted = nullptr;
		visited = nullptr;
		dict = nullptr;
		}
	}

RobustDictIterator& RobustDictIterator::operator++()
	{
	curr = dict->GetNextRobustIteration(this);
	return *this;
	}

} // namespace zeek
