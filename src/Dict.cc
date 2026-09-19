// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Dict.h"

#include <set>

#include "zeek/Hash.h"

#include "zeek/3rdparty/doctest.h"

namespace zeek {

TEST_SUITE_BEGIN("Dict");

TEST_CASE("dict construction") {
    PDict<int> dict;
    CHECK(! dict.IsOrdered());
    CHECK(dict.Length() == 0);

    PDict<int> dict2(ORDERED);
    CHECK(dict2.IsOrdered());
    CHECK(dict2.Length() == 0);
}

TEST_CASE("dict operation") {
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
    CHECK(lookup2 == (uint32_t*)nullptr);
    delete key2;

    dict.Insert(key, &val);
    dict.Remove(key);

    uint32_t val2 = 15;
    uint32_t key_val2 = 25;
    key2 = new detail::HashKey(key_val2);

    dict.Insert(key, &val);
    dict.Insert(key2, &val2);
    CHECK(dict.Length() == 2);

    dict.Clear();
    CHECK(dict.Length() == 0);

    delete key;
    delete key2;
}

TEST_CASE("dict nthentry") {
    PDict<uint32_t> unordered(UNORDERED);
    PDict<uint32_t> ordered(ORDERED);

    uint32_t val = 15;
    uint32_t key_val = 5;
    auto ukey = std::make_unique<detail::HashKey>(key_val);
    auto okey = std::make_unique<detail::HashKey>(key_val);

    uint32_t val2 = 10;
    uint32_t key_val2 = 25;
    auto ukey2 = std::make_unique<detail::HashKey>(key_val2);
    auto okey2 = std::make_unique<detail::HashKey>(key_val2);

    unordered.Insert(ukey.get(), &val);
    unordered.Insert(ukey2.get(), &val2);

    ordered.Insert(okey.get(), &val);
    ordered.Insert(okey2.get(), &val2);

    CHECK(unordered.NthEntry(0) == nullptr);
    CHECK(ordered.NthEntry(0) == &val);
    CHECK(ordered.NthEntry(1) == &val2);
    CHECK(ordered.NthEntry(2) == nullptr);
    CHECK(ordered.NthEntry(-1) == nullptr);
}

TEST_CASE("dict iteration") {
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
    std::set<uint32_t> seen_keys;

    for ( const auto& entry : dict ) {
        uint32_t k = *reinterpret_cast<const uint32_t*>(entry.GetKey());
        seen_keys.insert(k);
        count++;
    }

    CHECK(count == 2);
    CHECK(seen_keys.count(key_val) == 1);
    CHECK(seen_keys.count(key_val2) == 1);

    PDict<uint32_t>::iterator it;
    it = dict.begin();
    it = dict.end();
    PDict<uint32_t>::iterator it2 = it;

    delete key;
    delete key2;
}

TEST_CASE("dict robust iteration") {
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

        for ( ; it != dict.end_robust(); ++it ) {
            auto* v = it->value;
            count++;

            // Insert during first iteration step
            if ( count == 1 )
                dict.Insert(key3, &val3);
        }

        CHECK(count == 3);
    }

    {
        int count = 0;
        auto it = dict.begin_robust();

        for ( ; it != dict.end_robust(); ++it ) {
            auto* v = it->value;
            count++;

            // Insert and immediately remove during first step
            if ( count == 1 ) {
                auto k3_copy = new detail::HashKey(key_val3);
                dict.Insert(k3_copy, &val3);
                dict.Remove(k3_copy);
                delete k3_copy;
            }
        }

        // Should see only the 2 original entries (key3 was inserted
        // and removed, so it might or might not have been visited
        // depending on where in the list it landed).
        CHECK(count >= 2);
    }

    delete key;
    delete key2;
    delete key3;
}

TEST_CASE("dict ordered iteration") {
    PDict<uint32_t> dict(DictOrder::ORDERED);

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

    dict.Insert(key.get(), &val);
    dict.Insert(key2.get(), &val2);
    dict.Insert(key3.get(), &val3);

    int count = 0;

    for ( const auto& entry : dict ) {
        uint32_t k = *reinterpret_cast<const uint32_t*>(entry.GetKey());

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

    for ( const auto& entry : dict ) {
        uint32_t k = *reinterpret_cast<const uint32_t*>(entry.GetKey());

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

    for ( const auto& entry : dict ) {
        uint32_t k = *reinterpret_cast<const uint32_t*>(entry.GetKey());

        if ( count == 0 )
            CHECK(k == 5);
        else if ( count == 1 )
            CHECK(k == 45);
        else if ( count == 2 )
            CHECK(k == 35);

        count++;
    }
}

TEST_CASE("dict ordered robust iteration") {
    PDict<uint32_t> dict(DictOrder::ORDERED);

    uint32_t val = 15;
    uint32_t key_val = 5;
    auto key = std::make_unique<detail::HashKey>(key_val);

    uint32_t val2 = 10;
    uint32_t key_val2 = 25;
    auto key2 = std::make_unique<detail::HashKey>(key_val2);

    uint32_t val3 = 20;
    uint32_t key_val3 = 35;
    auto key3 = std::make_unique<detail::HashKey>(key_val3);

    dict.Insert(key.get(), &val);
    dict.Insert(key2.get(), &val2);
    dict.Insert(key3.get(), &val3);

    int count = 0;
    auto it = dict.begin_robust();

    for ( ; it != dict.end_robust(); ++it ) {
        count++;

        if ( count == 2 )
            dict.Remove(key.get());
    }

    CHECK(count == 3);
    CHECK(dict.Length() == 2);
}

class DictTestDummy {
public:
    DictTestDummy(int v) : v(v) {}
    ~DictTestDummy() = default;
    int v = 0;
};

TEST_CASE("dict robust iteration replacement") {
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

    for ( ; count != 2 && it != dict.end_robust(); ++count, ++it ) {
    }

    // Store off the value at this iterator index
    auto* old_val = it->value;

    // Replace it with something else
    auto k = it->GetHashKey();
    DictTestDummy* val4 = new DictTestDummy(50);
    auto* replaced = dict.Insert(k.get(), val4);
    CHECK(replaced == old_val);

    // Delete the original element
    delete old_val;

    // This shouldn't crash with AddressSanitizer
    for ( ; it != dict.end_robust(); ++it ) {
        auto* v2 = it->value;
        CHECK(v2->v == 50);
    }

    // Clean up the values that were NOT replaced.
    std::set<DictTestDummy*> all = {val1, val2, val3};
    all.erase(old_val);
    for ( auto* v : all )
        delete v;

    delete key1;
    delete key2;
    delete key3;
    delete val4;
}

TEST_CASE("dict iterator invalidation") {
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
void generic_delete_func(void* v) { free(v); }

} // namespace zeek
