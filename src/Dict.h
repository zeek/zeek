// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <algorithm>
#include <functional>
#include <list>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "zeek/Hash.h"
#include "zeek/Reporter.h"

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

// Lightweight view over a dictionary entry. Consumers access .value and
// .GetHashKey(); the key data points into the map's storage and is valid
// as long as the entry is not erased.
template<typename T>
class DictEntry {
public:
    T* value = nullptr;

    const char* GetKey() const { return key_data_; }
    uint32_t KeySize() const { return static_cast<uint32_t>(key_size_); }

    std::unique_ptr<HashKey> GetHashKey() const {
        auto h = HashKey::HashBytes(key_data_, key_size_);
        return std::make_unique<HashKey>(key_data_, key_size_, h);
    }

private:
    template<typename U>
    friend class zeek::Dictionary;
    template<typename U>
    friend class zeek::DictIterator;
    template<typename U>
    friend class zeek::RobustDictIterator;

    DictEntry(T* v, const char* key, size_t size) : value(v), key_data_(key), key_size_(size) {}
    DictEntry() = default;

    const char* key_data_ = nullptr;
    size_t key_size_ = 0;
};

} // namespace detail

template<typename T>
class Dictionary {
    struct KeyHasher {
        // Enables heterogeneous lookup with string_view keys.
        using is_transparent = void;
        size_t operator()(std::string_view k) const { return detail::HashKey::HashBytes(k.data(), k.size()); }
    };

    // The order list uses void* to break a circular type dependency:
    // MapEntry needs OrderList::iterator, but OrderList<MapNode*> would
    // need MapEntry to be complete. Accesses go through ToNode().
    using OrderList = std::list<void*>;

    struct MapEntry {
        T* value = nullptr;
        detail::hash_t hash = 0;
        typename OrderList::iterator order_it;
    };

    using Map = std::unordered_map<std::string, MapEntry, KeyHasher, std::equal_to<>>;
    using MapNode = typename Map::value_type;

    static MapNode* ToNode(void* p) { return static_cast<MapNode*>(p); }

public:
    explicit Dictionary(DictOrder ordering = UNORDERED, int initial_size = 0) : is_ordered_(ordering == ORDERED) {
        if ( initial_size > 0 )
            map_.reserve(initial_size);
    }

    ~Dictionary() { Clear(); }

    Dictionary(const Dictionary&) = delete;
    Dictionary& operator=(const Dictionary&) = delete;

    // --- Lookup ---

    T* Lookup(const detail::HashKey* key) const { return Lookup(key->Key(), key->Size(), key->Hash()); }

    T* Lookup(const void* key, int key_size, detail::hash_t /*h*/) const {
        auto sv = std::string_view(static_cast<const char*>(key), key_size);
        auto it = map_.find(sv);
        return it != map_.end() ? it->second.value : nullptr;
    }

    T* Lookup(const char* key) const {
        detail::HashKey h(key);
        return Lookup(&h);
    }

    // --- Insert ---

    T* Insert(detail::HashKey* key, T* val, bool* iterators_invalidated = nullptr) {
        return Insert(key->Key(), key->Size(), key->Hash(), val, true, iterators_invalidated);
    }

    T* Insert(const void* key, uint64_t key_size, detail::hash_t hash, T* val, bool copy_key,
              bool* iterators_invalidated = nullptr) {
        auto sv = std::string_view(static_cast<const char*>(key), key_size);
        // TODO: `copy_key` is unused -- remove parameter after deprecation.
        std::unique_ptr<const char[]> owned_key;
        if ( ! copy_key )
            owned_key.reset(static_cast<const char*>(key));

        auto it = map_.find(sv);
        if ( it != map_.end() ) {
            T* old = it->second.value;
            it->second.value = val;
            for ( auto* ri : robust_iterators_ )
                if ( ri->current_node_ == &*it )
                    ri->entry_.value = val;
            return old;
        }

        WarnIfNonRobustIterators(iterators_invalidated);

        if ( ! hash )
            hash = KeyHasher{}(sv);

        auto [new_it, inserted] = map_.emplace(std::string(sv), MapEntry{val, hash, {}});

        order_.push_back(&*new_it);
        new_it->second.order_it = std::prev(order_.end());

        if ( ! is_ordered_ )
            order_dirty_ = true;

        return nullptr;
    }

    T* Insert(const char* key, T* val, bool* iterators_invalidated = nullptr) {
        detail::HashKey h(key);
        return Insert(&h, val, iterators_invalidated);
    }

    // --- Remove ---

    T* Remove(const detail::HashKey* key, bool* iterators_invalidated = nullptr) {
        return Remove(key->Key(), key->Size(), key->Hash(), false, iterators_invalidated);
    }

    T* Remove(const void* key, int key_size, detail::hash_t /*hash*/, bool /*dont_delete*/ = false,
              bool* iterators_invalidated = nullptr) {
        auto sv = std::string_view(static_cast<const char*>(key), key_size);
        auto it = map_.find(sv);
        if ( it == map_.end() )
            return nullptr;

        WarnIfNonRobustIterators(iterators_invalidated);

        T* val = it->second.value;

        for ( auto* ri : robust_iterators_ ) {
            if ( ri->current_node_ == &*it ) {
                ri->Advance();
                ri->advanced_by_remove_ = true;
            }
        }

        order_.erase(it->second.order_it);
        map_.erase(it);
        return val;
    }

    T* RemoveEntry(const detail::HashKey* key, bool* iterators_invalidated = nullptr) {
        return Remove(key, iterators_invalidated);
    }
    T* RemoveEntry(const detail::HashKey& key, bool* iterators_invalidated = nullptr) {
        return Remove(&key, iterators_invalidated);
    }

    // --- Size / State ---

    int Length() const { return static_cast<int>(map_.size()); }
    [[deprecated]] int MaxLength() const { return Length(); }
    [[deprecated]] uint64_t NumCumulativeInserts() const { return 0; }
    [[deprecated]] int Capacity() const { return Length(); }
    [[deprecated]] int ExpectedCapacity() const { return Length(); }
    bool IsOrdered() const { return is_ordered_; }
    void SetDeleteFunc(dict_delete_func f) { delete_func_ = f; }

    T* NthEntry(int n) const {
        const void* key = nullptr;
        int key_len = 0;
        return NthEntry(n, key, key_len);
    }

    T* NthEntry(int n, const void*& key, int& key_size) const {
        if ( ! is_ordered_ || n < 0 || n >= Length() )
            return nullptr;
        auto it = order_.begin();
        std::advance(it, n);
        auto* node = ToNode(*it);
        key = node->first.data();
        key_size = static_cast<int>(node->first.size());
        return node->second.value;
    }

    T* NthEntry(int n, const char*& key) const {
        const void* k = nullptr;
        int key_len = 0;
        auto* result = NthEntry(n, k, key_len);
        key = static_cast<const char*>(k);
        return result;
    }

    void Clear() {
        auto robust_copy = robust_iterators_;
        for ( auto* ri : robust_copy )
            ri->Complete();

        if ( delete_func_ )
            for ( auto& [k, entry] : map_ )
                delete_func_(entry.value);

        map_.clear();
        order_.clear();
        order_dirty_ = false;
    }

    // --- Iteration ---

    using value_type = detail::DictEntry<T>;
    using iterator = DictIterator<T>;
    using const_iterator = iterator;

    iterator begin() const {
        SortOrderIfNeeded();
        return {this, order_.begin()};
    }
    iterator end() const { return {this, order_.end()}; }

    const_iterator cbegin() const { return begin(); }
    const_iterator cend() const { return end(); }

    RobustDictIterator<T> begin_robust() {
        SortOrderIfNeeded();
        return {this};
    }
    RobustDictIterator<T> end_robust() { return {}; }

private:
    friend class DictIterator<T>;
    friend class RobustDictIterator<T>;

    void SortOrderIfNeeded() const {
        if ( ! order_dirty_ )
            return;
        order_.sort([](void* a, void* b) { return (ToNode(a)->second.hash) < (ToNode(b)->second.hash); });
        for ( auto it = order_.begin(); it != order_.end(); ++it )
            ToNode(*it)->second.order_it = it;
        order_dirty_ = false;
    }

    void WarnIfNonRobustIterators(bool* iterators_invalidated) {
        if ( num_iterators_ > static_cast<int>(robust_iterators_.size()) ) {
            if ( iterators_invalidated )
                *iterators_invalidated = true;
            else
                reporter->InternalWarning("Dictionary modification possibly caused iterator invalidation");
        }
    }

    Map map_;
    mutable OrderList order_;
    bool is_ordered_ = false;
    mutable bool order_dirty_ = false;
    dict_delete_func delete_func_ = nullptr;
    mutable int num_iterators_ = 0;
    std::vector<RobustDictIterator<T>*> robust_iterators_;
};

// Dictionary iterator. Walks the order list, yielding DictEntry<T> views.
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
            --dict_->num_iterators_;
    }

    DictIterator(const DictIterator& o) : dict_(o.dict_), order_it_(o.order_it_), entry_(o.entry_) {
        if ( dict_ )
            ++dict_->num_iterators_;
    }

    DictIterator(DictIterator&& o) noexcept : dict_(o.dict_), order_it_(o.order_it_), entry_(o.entry_) {
        o.dict_ = nullptr;
    }

    DictIterator& operator=(const DictIterator& o) {
        if ( this == &o )
            return *this;
        if ( dict_ )
            --dict_->num_iterators_;
        dict_ = o.dict_;
        order_it_ = o.order_it_;
        entry_ = o.entry_;
        if ( dict_ )
            ++dict_->num_iterators_;
        return *this;
    }

    DictIterator& operator=(DictIterator&& o) noexcept {
        if ( this == &o )
            return *this;
        if ( dict_ )
            --dict_->num_iterators_;
        dict_ = o.dict_;
        order_it_ = o.order_it_;
        entry_ = o.entry_;
        o.dict_ = nullptr;
        return *this;
    }

    reference operator*() const { return entry_; }
    pointer operator->() const { return &entry_; }

    DictIterator& operator++() {
        ++order_it_;
        if ( order_it_ != dict_->order_.end() )
            UpdateFromOrder();
        return *this;
    }

    DictIterator operator++(int) {
        auto tmp(*this);
        ++*this;
        return tmp;
    }

    bool operator==(const DictIterator& o) const {
        if ( ! dict_ && ! o.dict_ )
            return true;
        if ( dict_ != o.dict_ )
            return false;
        return order_it_ == o.order_it_;
    }

private:
    friend class Dictionary<T>;

    using OrderIter = typename Dictionary<T>::OrderList::const_iterator;

    DictIterator(const Dictionary<T>* d, OrderIter it) : dict_(d), order_it_(it) {
        ++dict_->num_iterators_;
        if ( order_it_ != dict_->order_.end() )
            UpdateFromOrder();
    }

    void UpdateFromOrder() {
        auto* node = Dictionary<T>::ToNode(*order_it_);
        entry_.value = node->second.value;
        entry_.key_data_ = node->first.data();
        entry_.key_size_ = node->first.size();
    }

    const Dictionary<T>* dict_ = nullptr;
    OrderIter order_it_;
    mutable detail::DictEntry<T> entry_;
};

// Robust iterator backed by the order list. Survives arbitrary mutations
// because std::list iterators to non-erased elements are never invalidated.
// The Dictionary's Remove() advances any robust iterator pointing at the
// element being erased before the erase happens.
template<typename T>
class RobustDictIterator {
public:
    using value_type = detail::DictEntry<T>;
    using reference = detail::DictEntry<T>&;
    using pointer = detail::DictEntry<T>*;
    using difference_type = std::ptrdiff_t;
    using iterator_category = std::forward_iterator_tag;

    RobustDictIterator() = default;

    ~RobustDictIterator() { Complete(); }

    RobustDictIterator(const RobustDictIterator&) = delete;
    RobustDictIterator& operator=(const RobustDictIterator&) = delete;

    RobustDictIterator(RobustDictIterator&& o) noexcept
        : dict_(o.dict_),
          order_it_(o.order_it_),
          entry_(o.entry_),
          current_node_(o.current_node_),
          advanced_by_remove_(o.advanced_by_remove_) {
        if ( dict_ ) {
            auto& ri = dict_->robust_iterators_;
            std::ranges::replace(ri, &o, this);
            o.dict_ = nullptr;
        }
    }

    RobustDictIterator& operator=(RobustDictIterator&& o) noexcept {
        if ( this == &o )
            return *this;
        Complete();
        dict_ = o.dict_;
        order_it_ = o.order_it_;
        entry_ = o.entry_;
        current_node_ = o.current_node_;
        advanced_by_remove_ = o.advanced_by_remove_;
        if ( dict_ ) {
            auto& ri = dict_->robust_iterators_;
            std::ranges::replace(ri, &o, this);
            o.dict_ = nullptr;
        }
        return *this;
    }

    reference operator*() { return entry_; }
    pointer operator->() { return &entry_; }

    RobustDictIterator& operator++() {
        if ( advanced_by_remove_ )
            advanced_by_remove_ = false;
        else
            Advance();
        return *this;
    }

    bool operator==(const RobustDictIterator& o) const { return current_node_ == o.current_node_; }

private:
    friend class Dictionary<T>;

    using OrderIter = typename Dictionary<T>::OrderList::iterator;

    RobustDictIterator(Dictionary<T>* d) : dict_(d) {
        dict_->robust_iterators_.push_back(this);
        ++dict_->num_iterators_;
        order_it_ = dict_->order_.begin();
        if ( order_it_ != dict_->order_.end() )
            UpdateEntry();
    }

    void Advance() {
        if ( ! dict_ )
            return;
        ++order_it_;
        if ( order_it_ == dict_->order_.end() ) {
            current_node_ = nullptr;
            entry_ = {};
        }
        else
            UpdateEntry();
    }

    void UpdateEntry() {
        current_node_ = Dictionary<T>::ToNode(*order_it_);
        entry_.value = current_node_->second.value;
        entry_.key_data_ = current_node_->first.data();
        entry_.key_size_ = current_node_->first.size();
    }

    void Complete() {
        if ( ! dict_ )
            return;
        auto& ri = dict_->robust_iterators_;
        std::erase(ri, this);
        --dict_->num_iterators_;
        dict_ = nullptr;
        current_node_ = nullptr;
    }

    Dictionary<T>* dict_ = nullptr;
    OrderIter order_it_;
    detail::DictEntry<T> entry_;
    typename Dictionary<T>::MapNode* current_node_ = nullptr;
    bool advanced_by_remove_ = false;
};

template<typename T>
using PDict = Dictionary<T>;

} // namespace zeek
