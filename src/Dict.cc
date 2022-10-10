// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Dict.h"

#include "zeek/3rdparty/doctest.h"
#include "zeek/Hash.h"

namespace zeek
	{

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

TEST_CASE("dict ordered iteration")
	{
	PDict<uint32_t> dict(DictOrder::ORDERED);

	// These key values are specifically contrived to be inserted
	// into the dictionary in a different order by default.
	uint32_t val = 15;
	uint32_t key_val = 5;
	auto key = std::make_unique<detail::HashKey>(key_val);

	uint32_t val2 = 10;
	uint32_t key_val2 = 25;
	auto key2 = std::make_unique<detail::HashKey>(key_val2);

	uint32_t val3 = 30;
	uint32_t key_val3 = 45;
	auto key3 = std::make_unique<detail::HashKey>(key_val3);

	uint32_t val4 = 20;
	uint32_t key_val4 = 35;
	auto key4 = std::make_unique<detail::HashKey>(key_val4);

	// Only insert the first three to start with so we can test the order
	// being the same after a later insertion.
	dict.Insert(key.get(), &val);
	dict.Insert(key2.get(), &val2);
	dict.Insert(key3.get(), &val3);

	int count = 0;

	for ( const auto& entry : dict )
		{
		auto* v = static_cast<uint32_t*>(entry.value);
		uint32_t k = *(uint32_t*)entry.GetKey();

		// The keys should be returned in the same order we inserted
		// them, which is 5, 25, 45.
		if ( count == 0 )
			CHECK(k == 5);
		else if ( count == 1 )
			CHECK(k == 25);
		else if ( count == 2 )
			CHECK(k == 45);

		count++;
		}

	dict.Insert(key4.get(), &val4);
	count = 0;

	for ( const auto& entry : dict )
		{
		auto* v = static_cast<uint32_t*>(entry.value);
		uint32_t k = *(uint32_t*)entry.GetKey();

		// The keys should be returned in the same order we inserted
		// them, which is 5, 25, 45, 35.
		if ( count == 0 )
			CHECK(k == 5);
		else if ( count == 1 )
			CHECK(k == 25);
		else if ( count == 2 )
			CHECK(k == 45);
		else if ( count == 3 )
			CHECK(k == 35);

		count++;
		}

	dict.Remove(key2.get());
	count = 0;

	for ( const auto& entry : dict )
		{
		auto* v = static_cast<uint32_t*>(entry.value);
		uint32_t k = *(uint32_t*)entry.GetKey();

		// The keys should be returned in the same order we inserted
		// them, which is 5, 45, 35.
		if ( count == 0 )
			CHECK(k == 5);
		else if ( count == 1 )
			CHECK(k == 45);
		else if ( count == 2 )
			CHECK(k == 35);

		count++;
		}
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
	for ( ; count != 2 && it != dict.end_robust(); ++count, ++it ) { }

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
