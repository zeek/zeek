// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Dict.h"

#include "zeek/3rdparty/doctest.h"
#include "zeek/Hash.h"

namespace zeek
	{

// namespace detail

TEST_SUITE_BEGIN("Dict");

//to show outputs of unit tests, define PRINTF as fprintf by uncommenting fprintf.
//and run ./zeek --test -tc="dict verify clone performance"
#define PRINTF(fmt, args...) //fprintf(stderr, fmt, args)

struct ReportDuration
	{
	std::chrono::_V2::system_clock::time_point start;
	std::chrono::_V2::system_clock::time_point stop;

	void Start()
		{
		start = std::chrono::high_resolution_clock::now();
		}
	ReportDuration()
		{
		Start();
		}

	void Stop()
		{
		stop = std::chrono::high_resolution_clock::now();
		}
	long DurationMS()
		{
		auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
		long d = duration.count();
		return d;
		}
	void Report()
		{
		PRINTF("%ld ms\n", DurationMS());
		}
	~ReportDuration() { }
	};

TEST_CASE("dict verify clone performance")
	{
	// measure direct insert and clone insert 10 times for sizes 1M - 2M with 0.1M intervals.
	// calculate the average and compare them.
	constexpr int iMax = 3;
	constexpr int round = 3;
	constexpr int base = 1000000;
	constexpr int interval = 500000;
	long duration[iMax + 1][2][round]; // 10 times for average.
	ReportDuration rd;
	for ( int i = 0; i < iMax; i++ )
		{
		PRINTF("%d/%d\n", i, iMax);
		auto dictSize = base + i * interval;
		int* item = new int[dictSize];
		int* hash_order_item = new int[dictSize];
		for ( int j = 0; j < dictSize; j++ )
			item[j] = j;

		for ( auto r = 0; r < round; r++ )
			{
			PDict<int>* dict = new PDict<int>;
			rd.Start();
			for ( int j = 0; j < dictSize; j++ )
				{
				detail::HashKey* key = new detail::HashKey(item[j]);
				dict->Insert(key, &item[j]);
				}
			rd.Stop();
			duration[i][0][r] = rd.DurationMS();
			PRINTF("%20s: %8ld ms / %d\n", "fill", rd.DurationMS(), dictSize);
			if ( r == 0 )
				{
				int k = 0;
				for ( const auto& entry : *dict )
					{
					auto val = static_cast<int*>(entry.value);
					hash_order_item[k++] = *val;
					}
				}
			delete dict;
			}
		delete[] item;
		for ( auto r = 0; r < round; r++ )
			{
			PDict<int>* dictClone = new PDict<int>;
			rd.Start();
			for ( int j = 0; j < dictSize; j++ )
				{
				detail::HashKey* key = new detail::HashKey(hash_order_item[j]);
				dictClone->Insert(key, &hash_order_item[j]);
				}
			rd.Stop();
			duration[i][1][r] = rd.DurationMS();
			PRINTF("%20s: %8ld ms / %d\n", "fill/order", rd.DurationMS(), dictSize);
			delete dictClone;
			}
		delete[] hash_order_item;
		}
	PRINTF("%10s %8s %8s %10s\n", "size", "fill", "fill/order", "ratio");
	for ( int i = 0; i < iMax; i++ )
		{
		long d0 = 0;
		long d1 = 0;
		for ( auto r = 0; r < round; r++ )
			{
			d0 += duration[i][0][r];
			d1 += duration[i][1][r];
			}
		CHECK(d0 * 3 > d1);
		PRINTF("%10d %8ld %8ld %10f\n", base + i * interval, d0 / round, d1 / round,
		       float(d1) / d0);
		}
	}

TEST_CASE("dict measure clone")
	{
	constexpr int iMax = 3;
	long duration[iMax][4];
	constexpr int base = 1000000;
	constexpr int interval = 500000;
	ReportDuration rd;
	for ( auto i = 0; i < iMax; i++ )
		{
		auto dictSize = base + i * interval;
		int* v = new int[dictSize];
		for ( int j = 0; j < dictSize; j++ )
			v[j] = j;
		PDict<int>* dict = new PDict<int>;
		PRINTF("%20d\n", dictSize);
		rd.Start();
		for ( int j = 0; j < dictSize; j++ )
			{
			detail::HashKey* key = new detail::HashKey(v[j]);
			dict->Insert(key, &v[j]);
			}
		rd.Stop();
		duration[i][0] = rd.DurationMS();
		PRINTF("%20s: %8ld ms\n", "fill", rd.DurationMS());
		int* v2 = new int[dictSize];
		int k = 0;
		for ( const auto& entry : *dict )
			{
			auto val = static_cast<int*>(entry.value);
			v2[k++] = *val;
			}
		delete dict;
		delete[] v;

		PDict<int>* dictClone = new PDict<int>;
		rd.Start();
		for ( int j = 0; j < dictSize; j++ )
			{
			detail::HashKey* key = new detail::HashKey(v2[j]);
			dictClone->Insert(key, &v2[j]);
			}
		rd.Stop();
		duration[i][1] = rd.DurationMS();
		PRINTF("%20s: %8ld ms\n", "fill/order", rd.DurationMS());
		delete dictClone;
		PDict<int>* dictClone2 = new PDict<int>(UNORDERED, dictSize * 2);
		rd.Start();
		for ( int j = 0; j < dictSize; j++ )
			{
			detail::HashKey* key = new detail::HashKey(v2[j]);
			dictClone2->Insert(key, &v2[j]);
			}
		rd.Stop();
		duration[i][2] = rd.DurationMS();
		PRINTF("%20s: %8ld ms\n", "fill/order/size", rd.DurationMS());
		delete dictClone2;

		PDict<int>* dictClone3 = new PDict<int>;
		std::random_shuffle(v2, v2 + dictSize);
		rd.Start();
		for ( int j = 0; j < dictSize; j++ )
			{
			detail::HashKey* key = new detail::HashKey(v2[j]);
			dictClone3->Insert(key, &v2[j]);
			}
		rd.Stop();
		duration[i][3] = rd.DurationMS();
		PRINTF("%20s: %8ld ms\n", "fill/random", rd.DurationMS());
		delete dictClone3;
		delete[] v2;
		}
	PRINTF("%10s %8s %10s %15s %8s\n", "size", "fill", "fill/order", "fill/order/size",
	       "fill/random");
	for ( int i = 0; i < iMax; i++ )
		{
		PRINTF("%10d %8ld %10ld %15ld %8ld\n", base + i * interval, duration[i][0], duration[i][1],
		       duration[i][2], duration[i][3]);
		}
	}

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

	int count = 0;

	for ( const auto& entry : dict )
		{
		auto* v = static_cast<uint32_t*>(entry.value);
		uint64_t k = *(uint32_t*)entry.GetKey();

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

		{
		int count = 0;
		auto it = dict.begin_robust();

		for ( ; it != dict.end_robust(); ++it )
			{
			auto* v = it->value;
			uint64_t k = *(uint32_t*)it->GetKey();

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
			auto* v = it->value;
			uint64_t k = *(uint32_t*)it->GetKey();

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
	DictTestDummy(int v) : v(v) { }
	~DictTestDummy() { }
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
	auto* v = it->value;

	// Replace it with something else
	auto k = it->GetHashKey();
	DictTestDummy* val4 = new DictTestDummy(50);
	dict.Insert(k.get(), val4);

	// Delete the original element
	delete val2;

	// This shouldn't crash with AddressSanitizer
	for ( ; it != dict.end_robust(); ++it )
		{
		uint64_t k = *(uint32_t*)it->GetKey();
		auto* v = it->value;
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

	auto it = dict.begin();
	iterators_invalidated = false;
	dict.Remove(key3, &iterators_invalidated);
	// Key doesn't exist, nothing to remove, iteration not invalidated.
	CHECK(! iterators_invalidated);

	iterators_invalidated = false;
	dict.Insert(key, &val2, &iterators_invalidated);
	// Key exists, value gets overwritten, iteration not invalidated.
	CHECK(! iterators_invalidated);

	iterators_invalidated = false;
	dict.Remove(key2, &iterators_invalidated);
	// Key exists, gets removed, iteration is invalidated.
	CHECK(iterators_invalidated);

	it = dict.begin();
	iterators_invalidated = false;
	dict.Insert(key3, &val3, &iterators_invalidated);
	// Key doesn't exist, gets inserted, iteration is invalidated.
	CHECK(iterators_invalidated);

	CHECK(dict.Length() == 2);
	CHECK(*static_cast<uint32_t*>(dict.Lookup(key)) == val2);
	CHECK(*static_cast<uint32_t*>(dict.Lookup(key3)) == val3);
	CHECK(static_cast<uint32_t*>(dict.Lookup(key2)) == nullptr);

	delete key;
	delete key2;
	delete key3;
	}

// private
void generic_delete_func(void* v)
	{
	free(v);
	}

	} // namespace zeek
