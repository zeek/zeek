// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <cstring>
#include <memory>
#include <unordered_set>
#include <vector>

#include "zeek/3rdparty/ankerl/unordered_dense.h"
#include "zeek/3rdparty/plf_hive.h"
#include "zeek/Hash.h"
#include "zeek/Obj.h"
#include "zeek/Reporter.h"
#include "zeek/util.h"

// Type for function to be called when deleting elements.
using dict_delete_func = void (*)(void*);

namespace zeek {

template<typename T>
class Dictionary;

template<typename T>
class DictIterator;

template<typename T>
class RobustDictIterator;

enum DictOrder : uint8_t { ORDERED, UNORDERED };

// A dict_delete_func that just calls delete.
extern void generic_delete_func(void*);

namespace detail {

/**
 * An entry stored in the dictionary. Owns its key bytes.
 */
template<typename T>
class DictEntry {
public:
    uint32_t key_size = 0;
    uint32_t hash = 0;
    T* value = nullptr;

    union {
        char key_here[8];
        char* key;
    };

    DictEntry() { key_here[0] = '\0'; }

    DictEntry(void* arg_key, uint32_t arg_key_size, hash_t arg_hash, T* val, bool copy_key = false)
        : key_size(arg_key_size), hash(static_cast<uint32_t>(arg_hash)), value(val) {
        if ( ! arg_key ) {
            key_here[0] = '\0';
            return;
        }

        if ( key_size <= 8 ) {
            memcpy(key_here, arg_key, key_size);
            if ( ! copy_key )
                delete[] reinterpret_cast<char*>(arg_key);
        }
        else {
            if ( copy_key ) {
                key = new char[key_size];
                memcpy(key, arg_key, key_size);
            }
            else {
                key = reinterpret_cast<char*>(arg_key);
            }
        }
    }

    ~DictEntry() {
        if ( key_size > 8 )
            delete[] key;
    }

    DictEntry(const DictEntry& other) : key_size(other.key_size), hash(other.hash), value(other.value) {
        if ( key_size <= 8 )
            memcpy(key_here, other.key_here, 8);
        else {
            key = new char[key_size];
            memcpy(key, other.key, key_size);
        }
    }

    DictEntry& operator=(const DictEntry& other) {
        if ( this == &other )
            return *this;
        if ( key_size > 8 )
            delete[] key;
        key_size = other.key_size;
        hash = other.hash;
        value = other.value;
        if ( key_size <= 8 )
            memcpy(key_here, other.key_here, 8);
        else {
            key = new char[key_size];
            memcpy(key, other.key, key_size);
        }
        return *this;
    }

    DictEntry(DictEntry&& other) noexcept : key_size(other.key_size), hash(other.hash), value(other.value) {
        if ( key_size <= 8 )
            memcpy(key_here, other.key_here, 8);
        else {
            key = other.key;
            other.key_size = 0;
            other.key = nullptr;
        }
        other.value = nullptr;
    }

    DictEntry& operator=(DictEntry&& other) noexcept {
        if ( this == &other )
            return *this;
        if ( key_size > 8 )
            delete[] key;
        key_size = other.key_size;
        hash = other.hash;
        value = other.value;
        if ( key_size <= 8 )
            memcpy(key_here, other.key_here, 8);
        else {
            key = other.key;
            other.key_size = 0;
            other.key = nullptr;
        }
        other.value = nullptr;
        return *this;
    }

    void Clear() {
        if ( key_size > 8 )
            delete[] key;
        key_size = 0;
        hash = 0;
        value = nullptr;
    }

    const char* GetKey() const { return key_size <= 8 ? key_here : key; }
    std::unique_ptr<detail::HashKey> GetHashKey() const {
        return std::make_unique<detail::HashKey>(GetKey(), key_size, hash);
    }

    bool Equal(const char* arg_key, uint32_t arg_key_size, hash_t arg_hash) const {
        return static_cast<uint32_t>(arg_hash) == hash && key_size == arg_key_size &&
               memcmp(GetKey(), arg_key, key_size) == 0;
    }

    bool operator==(const DictEntry& r) const { return Equal(r.GetKey(), r.key_size, r.hash); }
    bool operator!=(const DictEntry& r) const { return ! Equal(r.GetKey(), r.key_size, r.hash); }
};

using DictEntryVec = std::vector<detail::HashKey>;

// Key type stored in the index map. Points into the hive entry's key storage (stable pointers).
struct StoredKey {
    const char* data = nullptr;
    uint32_t size = 0;
    uint32_t hash = 0;
};

struct DictHash {
    using is_transparent = void;
    auto operator()(const StoredKey& k) const noexcept -> uint64_t { return k.hash; }
};

struct DictEqual {
    using is_transparent = void;
    bool operator()(const StoredKey& a, const StoredKey& b) const {
        return a.hash == b.hash && a.size == b.size && memcmp(a.data, b.data, a.size) == 0;
    }
};

} // namespace detail

template<typename T>
class DictIterator {
public:
    using value_type = detail::DictEntry<T>;
    using reference = detail::DictEntry<T>&;
    using pointer = detail::DictEntry<T>*;
    using difference_type = std::ptrdiff_t;
    using iterator_category = std::forward_iterator_tag;

    DictIterator() = default;

    ~DictIterator() {
        if ( dict_ )
            dict_->DecrNonRobustIters();
    }

    DictIterator(const DictIterator& other)
        : dict_(other.dict_), hive_iter_(other.hive_iter_), ordered_pos_(other.ordered_pos_) {
        if ( dict_ )
            dict_->IncrNonRobustIters();
    }

    DictIterator& operator=(const DictIterator& other) {
        if ( this == &other )
            return *this;
        if ( dict_ )
            dict_->DecrNonRobustIters();
        dict_ = other.dict_;
        hive_iter_ = other.hive_iter_;
        ordered_pos_ = other.ordered_pos_;
        if ( dict_ )
            dict_->IncrNonRobustIters();
        return *this;
    }

    DictIterator(DictIterator&& other) noexcept
        : dict_(other.dict_), hive_iter_(other.hive_iter_), ordered_pos_(other.ordered_pos_) {
        other.dict_ = nullptr;
    }

    DictIterator& operator=(DictIterator&& other) noexcept {
        if ( this == &other )
            return *this;
        if ( dict_ )
            dict_->DecrNonRobustIters();
        dict_ = other.dict_;
        hive_iter_ = other.hive_iter_;
        ordered_pos_ = other.ordered_pos_;
        other.dict_ = nullptr;
        return *this;
    }

    reference operator*() const {
        if ( dict_ && dict_->IsOrdered() )
            return *dict_->LookupEntryByOrderIndex(ordered_pos_);
        return const_cast<reference>(*hive_iter_);
    }

    pointer operator->() const {
        if ( dict_ && dict_->IsOrdered() )
            return dict_->LookupEntryByOrderIndex(ordered_pos_);
        return const_cast<pointer>(&(*hive_iter_));
    }

    DictIterator& operator++() {
        if ( dict_ && dict_->IsOrdered() )
            ++ordered_pos_;
        else
            ++hive_iter_;
        return *this;
    }

    DictIterator operator++(int) {
        auto temp(*this);
        ++*this;
        return temp;
    }

    bool operator==(const DictIterator& that) const {
        if ( dict_ != that.dict_ )
            return false;
        if ( dict_ && dict_->IsOrdered() )
            return ordered_pos_ == that.ordered_pos_;
        return hive_iter_ == that.hive_iter_;
    }

    bool operator!=(const DictIterator& that) const { return ! (*this == that); }

private:
    friend class Dictionary<T>;

    // Constructor for unordered iteration (hive-based).
    DictIterator(const Dictionary<T>* d, typename plf::hive<detail::DictEntry<T>>::iterator iter)
        : dict_(d), hive_iter_(iter) {
        if ( dict_ )
            dict_->IncrNonRobustIters();
    }

    // Constructor for ordered iteration (index-based).
    DictIterator(const Dictionary<T>* d, size_t pos) : dict_(d), ordered_pos_(pos) {
        if ( dict_ )
            dict_->IncrNonRobustIters();
    }

    const Dictionary<T>* dict_ = nullptr;
    typename plf::hive<detail::DictEntry<T>>::iterator hive_iter_;
    size_t ordered_pos_ = 0;
};

// An iterator that survives insert and erase during iteration. Elements inserted
// mid-iteration are delivered before iteration ends; elements erased mid-iteration
// (including the current one) are skipped.
//
// State invariants:
//   curr_         — the element currently delivered by operator*. nullptr iff the
//                   iterator has reached the end (Complete() has run, dict_ is null).
//   hive_iter_    — the advance cursor into the hive: where operator++ resumes normal
//                   traversal. May temporarily lag behind curr_ when we've just drained
//                   a pending-insert (hive_iter_ still points at the last "hive" element
//                   we delivered).
//   pending_inserts_           — LIFO queue of hive iterators for elements inserted
//                                during this iteration that we haven't yet delivered.
//                                operator++ drains this before advancing hive_iter_.
//   inserted_during_iteration_ — set of every element pointer ever inserted during
//                                this iteration. operator++ and NotifyErase consult it
//                                to skip elements that already came via pending_inserts_,
//                                so we don't deliver a mid-iteration insert twice.
//   already_advanced_          — set by NotifyErase when it erases curr_ and updates
//                                curr_ to the next element on behalf of the next ++.
//                                The next ++ then consumes curr_ without re-advancing.
template<typename T>
class RobustDictIterator {
public:
    using hive_iterator = typename plf::hive<detail::DictEntry<T>>::iterator;
    using value_type = detail::DictEntry<T>;
    using reference = detail::DictEntry<T>&;
    using pointer = detail::DictEntry<T>*;
    using difference_type = std::ptrdiff_t;
    using iterator_category = std::forward_iterator_tag;

    RobustDictIterator() = default;

    RobustDictIterator(Dictionary<T>* d) {
        // On an empty dict, leave the iterator in its default-constructed state
        // (dict_ == nullptr, curr_ == nullptr), which compares equal to end_robust().
        // This avoids a register/unregister round-trip.
        if ( d->entries_.empty() )
            return;
        dict_ = d;
        dict_->RegisterRobustIterator(this);
        hive_iter_ = dict_->entries_.begin();
        curr_ = &(*hive_iter_);
    }

    RobustDictIterator(const RobustDictIterator& other) : dict_(nullptr), curr_(nullptr) { *this = other; }

    RobustDictIterator(RobustDictIterator&& other) noexcept : dict_(nullptr), curr_(nullptr) {
        *this = std::move(other);
    }

    ~RobustDictIterator() { Complete(); }

    reference operator*() { return *curr_; }
    pointer operator->() { return curr_; }

    RobustDictIterator& operator++() {
        if ( ! dict_ ) {
            curr_ = nullptr;
            return *this;
        }

        // Drain pending inserts first (elements inserted during iteration).
        // These take priority over normal advancement.
        if ( ! pending_inserts_.empty() ) {
            auto it = pending_inserts_.back();
            pending_inserts_.pop_back();
            curr_ = &(*it);
            already_advanced_ = false;
            return *this;
        }

        // If NotifyErase already set curr_ to the next value, just consume it.
        if ( already_advanced_ ) {
            already_advanced_ = false;
            if ( ! curr_ )
                Complete();
            return *this;
        }

        // Advance in hive, skipping elements that were inserted during this iteration
        // (they were already delivered via pending_inserts_).
        while ( true ) {
            ++hive_iter_;
            if ( hive_iter_ == dict_->entries_.end() ) {
                Complete();
                return *this;
            }
            if ( inserted_during_iteration_.find(&(*hive_iter_)) == inserted_during_iteration_.end() ) {
                curr_ = &(*hive_iter_);
                return *this;
            }
        }
    }

    RobustDictIterator operator++(int) {
        auto temp(*this);
        ++*this;
        return temp;
    }

    RobustDictIterator& operator=(const RobustDictIterator& other) {
        if ( this == &other )
            return *this;

        Complete();

        if ( other.dict_ ) {
            dict_ = other.dict_;
            hive_iter_ = other.hive_iter_;
            pending_inserts_ = other.pending_inserts_;
            inserted_during_iteration_ = other.inserted_during_iteration_;
            curr_ = other.curr_;
            already_advanced_ = other.already_advanced_;
            dict_->RegisterRobustIterator(this);
        }

        return *this;
    }

    RobustDictIterator& operator=(RobustDictIterator&& other) noexcept {
        if ( this == &other )
            return *this;

        Complete();

        if ( other.dict_ ) {
            dict_ = other.dict_;
            hive_iter_ = other.hive_iter_;
            pending_inserts_ = std::move(other.pending_inserts_);
            inserted_during_iteration_ = std::move(other.inserted_during_iteration_);
            curr_ = other.curr_;
            already_advanced_ = other.already_advanced_;

            dict_->UnregisterRobustIterator(&other);
            dict_->RegisterRobustIterator(this);
            other.dict_ = nullptr;
            other.curr_ = nullptr;
        }

        return *this;
    }

    bool operator==(const RobustDictIterator& that) const { return curr_ == that.curr_; }
    bool operator!=(const RobustDictIterator& that) const { return curr_ != that.curr_; }

private:
    friend class Dictionary<T>;

    void Complete() {
        if ( dict_ ) {
            dict_->UnregisterRobustIterator(this);
            dict_ = nullptr;
        }
        curr_ = nullptr;
        pending_inserts_.clear();
        inserted_during_iteration_.clear();
        already_advanced_ = false;
    }

    void NotifyInsert(hive_iterator inserted_iter) {
        pending_inserts_.push_back(inserted_iter);
        inserted_during_iteration_.insert(&(*inserted_iter));
    }

    void NotifyErase(hive_iterator erased_iter) {
        // Remove from pending if it was inserted during iteration but not yet visited.
        pending_inserts_.erase(std::remove(pending_inserts_.begin(), pending_inserts_.end(), erased_iter),
                               pending_inserts_.end());
        inserted_during_iteration_.erase(&(*erased_iter));

        // Check if the erased element is what curr_ currently points at.
        // curr_ might differ from hive_iter_ when we drained from pending_inserts_.
        bool is_current = (curr_ == &(*erased_iter));

        // If the erased element is what hive_iter_ points at, advance hive_iter_ past it
        // (it will be invalidated by the upcoming hive erase).
        if ( hive_iter_ == erased_iter ) {
            ++hive_iter_;
            while ( hive_iter_ != dict_->entries_.end() &&
                    inserted_during_iteration_.find(&(*hive_iter_)) != inserted_during_iteration_.end() )
                ++hive_iter_;
        }

        if ( is_current ) {
            // The element we're currently "at" was erased. Update curr_.
            if ( ! pending_inserts_.empty() ) {
                auto it = pending_inserts_.back();
                pending_inserts_.pop_back();
                curr_ = &(*it);
            }
            else if ( dict_ && hive_iter_ != dict_->entries_.end() ) {
                curr_ = &(*hive_iter_);
            }
            else {
                curr_ = nullptr;
            }
            already_advanced_ = true;
        }
    }

    void NotifyValueUpdate(hive_iterator updated_iter, T* new_val) {
        if ( curr_ == &(*updated_iter) )
            curr_->value = new_val;

        for ( auto& pi : pending_inserts_ ) {
            if ( pi == updated_iter )
                pi->value = new_val;
        }
    }

    Dictionary<T>* dict_ = nullptr;
    hive_iterator hive_iter_;
    std::vector<hive_iterator> pending_inserts_;
    // Entries inserted during this iteration, keyed by DictEntry pointer. Hive
    // guarantees pointer stability, so &(*iter) is a valid long-lived key.
    // Hashed set (O(1)) beats std::set<hive_iterator> (O(log n) per op) across
    // the three hot paths that touch this (NotifyInsert, NotifyErase, operator++).
    std::unordered_set<detail::DictEntry<T>*> inserted_during_iteration_;
    detail::DictEntry<T>* curr_ = nullptr;
    bool already_advanced_ = false;
};

/**
 * A dictionary type backed by plf::hive (stable iterators, cache-friendly iteration)
 * and ankerl::unordered_dense::map (fast Robin Hood lookup with backward-shift deletion).
 *
 * The dictionary is effectively a hashmap from hashed keys to values. The dictionary owns
 * the keys but not the values.
 */
template<typename T>
class Dictionary {
public:
    using hive_iterator = typename plf::hive<detail::DictEntry<T>>::iterator;

    explicit Dictionary(DictOrder ordering = UNORDERED, int initial_size = 0) {
        if ( ordering == ORDERED )
            order_ = std::make_unique<std::vector<hive_iterator>>();
    }

    ~Dictionary() { Clear(); }

    // Lookup by HashKey.
    T* Lookup(const detail::HashKey* key) const { return Lookup(key->Key(), key->Size(), key->Hash()); }

    // Lookup by raw key data.
    T* Lookup(const void* key, int key_size, detail::hash_t h) const {
        detail::StoredKey sk{reinterpret_cast<const char*>(key), static_cast<uint32_t>(key_size),
                             static_cast<uint32_t>(h)};
        auto it = index_.find(sk);
        if ( it == index_.end() )
            return nullptr;
        return it->second->value;
    }

    T* Lookup(const char* key) const {
        detail::HashKey h(key);
        return Lookup(&h);
    }

    // Insert. Returns previous value if key existed, nullptr otherwise.
    T* Insert(detail::HashKey* key, T* val, bool* iterators_invalidated = nullptr) {
        return Insert(key->TakeKey(), key->Size(), key->Hash(), val, false, iterators_invalidated);
    }

    T* Insert(void* key, uint64_t key_size, detail::hash_t hash, T* val, bool copy_key,
              bool* iterators_invalidated = nullptr) {
        if ( key_size > UINT32_MAX ) {
            auto loc = detail::GetCurrentLocation();
            reporter->RuntimeError(&loc,
                                   "Attempted to create DictEntry with excessively large key "
                                   "(%" PRIu64 " > %u)",
                                   key_size, UINT32_MAX);
        }

        uint32_t ks = static_cast<uint32_t>(key_size);
        uint32_t h = static_cast<uint32_t>(hash);

        // Check if key already exists.
        detail::StoredKey lookup_key{reinterpret_cast<const char*>(key), ks, h};
        auto idx_it = index_.find(lookup_key);

        if ( idx_it != index_.end() ) {
            // Key exists — update value.
            T* old_val = idx_it->second->value;
            idx_it->second->value = val;

            // Notify robust iterators of value change.
            for ( auto* ri : robust_iterators_ )
                ri->NotifyValueUpdate(idx_it->second, val);

            if ( ! copy_key )
                delete[] reinterpret_cast<char*>(key);
            return old_val;
        }

        // Signal to the caller that a non-robust iterator may have been
        // semantically invalidated (for script-level loop-modification warnings).
        if ( iterators_invalidated && HasNonRobustIterators() )
            *iterators_invalidated = true;

        // Create entry in hive. DictEntry constructor takes ownership of key (or copies it).
        auto hive_it = entries_.emplace(detail::DictEntry<T>(key, ks, hash, val, copy_key));

        // Insert into index. StoredKey points at the hive entry's key storage (stable pointer).
        detail::StoredKey stored{hive_it->GetKey(), hive_it->key_size, hive_it->hash};
        index_.emplace(stored, hive_it);

        // Record in order vector — hive iterators are stable under subsequent ops.
        if ( order_ )
            order_->push_back(hive_it);

        num_entries_++;
        cum_entries_++;
        if ( num_entries_ > max_entries_ )
            max_entries_ = num_entries_;

        // Notify robust iterators.
        for ( auto* ri : robust_iterators_ )
            ri->NotifyInsert(hive_it);

        return nullptr;
    }

    T* Insert(const char* key, T* val, bool* iterators_invalidated = nullptr) {
        detail::HashKey h(key);
        return Insert(&h, val, iterators_invalidated);
    }

    // Remove. Returns the value if found, nullptr otherwise.
    T* Remove(const detail::HashKey* key, bool* iterators_invalidated = nullptr) {
        return Remove(key->Key(), key->Size(), key->Hash(), false, iterators_invalidated);
    }

    T* Remove(const void* key, int key_size, detail::hash_t hash, bool dont_delete = false,
              bool* iterators_invalidated = nullptr) {
        uint32_t ks = static_cast<uint32_t>(key_size);
        uint32_t h = static_cast<uint32_t>(hash);

        detail::StoredKey sk{reinterpret_cast<const char*>(key), ks, h};
        auto idx_it = index_.find(sk);
        if ( idx_it == index_.end() )
            return nullptr;

        if ( iterators_invalidated && HasNonRobustIterators() )
            *iterators_invalidated = true;

        auto hive_it = idx_it->second;
        T* val = hive_it->value;

        // Notify robust iterators before erasing.
        for ( auto* ri : robust_iterators_ )
            ri->NotifyErase(hive_it);

        // Remove from order vector — iterator compare is cheap (group_number + pointer).
        if ( order_ ) {
            auto pos = std::find(order_->begin(), order_->end(), hive_it);
            if ( pos != order_->end() )
                order_->erase(pos);
        }

        // Erase from hive — destructor handles key cleanup.
        entries_.erase(hive_it);

        // Erase from index.
        index_.erase(idx_it);

        num_entries_--;

        return val;
    }

    T* RemoveEntry(const detail::HashKey* key, bool* iterators_invalidated = nullptr) {
        return Remove(key->Key(), key->Size(), key->Hash(), false, iterators_invalidated);
    }
    T* RemoveEntry(const detail::HashKey& key, bool* iterators_invalidated = nullptr) {
        return Remove(key.Key(), key.Size(), key.Hash(), false, iterators_invalidated);
    }

    int Length() const { return static_cast<int>(num_entries_); }
    int MaxLength() const { return static_cast<int>(max_entries_); }
    uint64_t NumCumulativeInserts() const { return cum_entries_; }
    bool IsOrdered() const { return order_ != nullptr; }

    T* NthEntry(int n) const {
        const void* key;
        int key_len;
        return NthEntry(n, key, key_len);
    }

    T* NthEntry(int n, const void*& key, int& key_size) const {
        if ( ! order_ || n < 0 || n >= Length() )
            return nullptr;

        auto it = order_->at(n);
        key = it->GetKey();
        key_size = static_cast<int>(it->key_size);
        return it->value;
    }

    T* NthEntry(int n, const char*& key) const {
        int key_len;
        const void* k;
        auto* result = NthEntry(n, k, key_len);
        key = reinterpret_cast<const char*>(k);
        return result;
    }

    void SetDeleteFunc(dict_delete_func f) { delete_func_ = f; }

    void Clear() {
        // Invoke delete function on all values.
        if ( delete_func_ ) {
            for ( auto& entry : entries_ )
                delete_func_(entry.value);
        }

        // Destructors handle key cleanup.
        entries_.clear();
        index_.clear();

        if ( order_ )
            order_->clear();

        // Complete all robust iterators.
        auto iters_copy = robust_iterators_;
        for ( auto* ri : iters_copy )
            ri->Complete();
        robust_iterators_.clear();

        num_entries_ = 0;
        max_entries_ = 0;
    }

    // Type traits for compatibility.
    using value_type = detail::DictEntry<T>;
    using pointer = detail::DictEntry<T>*;
    using const_pointer = const detail::DictEntry<T>*;

    // Iterator support.
    using iterator = DictIterator<T>;
    using const_iterator = const iterator;

    iterator begin() {
        if ( IsOrdered() )
            return iterator(this, size_t(0));
        return iterator(this, entries_.begin());
    }

    iterator end() {
        if ( IsOrdered() )
            return iterator(this, static_cast<size_t>(Length()));
        return iterator(this, entries_.end());
    }

    const_iterator begin() const {
        if ( IsOrdered() )
            return iterator(this, size_t(0));
        return iterator(this, const_cast<Dictionary*>(this)->entries_.begin());
    }

    const_iterator end() const {
        if ( IsOrdered() )
            return iterator(this, static_cast<size_t>(Length()));
        return iterator(this, const_cast<Dictionary*>(this)->entries_.end());
    }

    const_iterator cbegin() const { return begin(); }
    const_iterator cend() const { return end(); }

    RobustDictIterator<T> begin_robust() {
        if ( IsOrdered() )
            reporter->InternalError("RobustIterators are not currently supported for ordered dictionaries");
        return RobustDictIterator<T>(this);
    }

    RobustDictIterator<T> end_robust() { return RobustDictIterator<T>(); }

private:
    friend class DictIterator<T>;
    friend class RobustDictIterator<T>;

    detail::DictEntry<T>* LookupEntryByOrderIndex(size_t n) const {
        if ( ! order_ || n >= order_->size() )
            return nullptr;
        return &(*order_->at(n));
    }

    void IncrNonRobustIters() const { ++num_non_robust_iters_; }
    void DecrNonRobustIters() const {
        if ( num_non_robust_iters_ > 0 )
            --num_non_robust_iters_;
    }

    bool HasNonRobustIterators() const { return num_non_robust_iters_ > 0; }

    void RegisterRobustIterator(RobustDictIterator<T>* ri) { robust_iterators_.push_back(ri); }

    void UnregisterRobustIterator(RobustDictIterator<T>* ri) {
        robust_iterators_.erase(std::remove(robust_iterators_.begin(), robust_iterators_.end(), ri),
                                robust_iterators_.end());
    }

    // Storage: hive owns entries, index provides O(1) lookup.
    plf::hive<detail::DictEntry<T>> entries_;
    ankerl::unordered_dense::map<detail::StoredKey, typename plf::hive<detail::DictEntry<T>>::iterator,
                                 detail::DictHash, detail::DictEqual>
        index_;

    // Ordered dictionaries maintain insertion order via a vector of hive iterators.
    // plf::hive iterators are stable under insert/erase of other elements, so they
    // can be parked here indefinitely and dereferenced directly without a hash lookup.
    std::unique_ptr<std::vector<hive_iterator>> order_;

    uint32_t num_entries_ = 0;
    uint32_t max_entries_ = 0;
    uint64_t cum_entries_ = 0;

    mutable uint32_t num_non_robust_iters_ = 0;
    dict_delete_func delete_func_ = nullptr;
    std::vector<RobustDictIterator<T>*> robust_iterators_;
};

template<typename T>
using PDict = Dictionary<T>;

} // namespace zeek
