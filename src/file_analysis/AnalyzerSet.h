// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <queue>

#include "zeek/Dict.h"
#include "zeek/Tag.h"
#include "zeek/Val.h"

namespace zeek {

class RecordVal;
using RecordValPtr = IntrusivePtr<RecordVal>;

namespace file_analysis {

class Analyzer;
class File;

namespace detail {

/**
 * A set of file analysis analyzers indexed by an \c AnalyzerArgs (script-layer
 * type) value.  Allows queueing of addition/removals so that those
 * modifications can happen at well-defined times (e.g. to make sure a loop
 * iterator isn't invalidated).
 */
class AnalyzerSet {
public:
    /**
     * Constructor.  Nothing special.
     * @param arg_file the file to which all analyzers in the set are attached.
     */
    explicit AnalyzerSet(File* arg_file);

    /**
     * Destructor.  Any queued analyzer additions/removals are aborted and
     * will not occur.
     */
    ~AnalyzerSet();

    /**
     * Looks up an analyzer by its tag and arguments.
     * @param tag an analyzer tag.
     * @param args an \c AnalyzerArgs record.
     * @return pointer to an analyzer instance, or a null pointer if not found.
     */
    Analyzer* Find(const zeek::Tag& tag, RecordValPtr args);

    /**
     * Attach an analyzer to #file immediately.
     * @param tag the analyzer tag of the file analyzer to add.
     * @param args an \c AnalyzerArgs value which specifies an analyzer.
     * @return true if analyzer was instantiated/attached, else false.
     */
    bool Add(const zeek::Tag& tag, RecordValPtr args);

    /**
     * Queue the attachment of an analyzer to #file.
     * @param tag the analyzer tag of the file analyzer to add.
     * @param args an \c AnalyzerArgs value which specifies an analyzer.
     * @return if successful, a pointer to a newly instantiated analyzer else
     * a null pointer.  The caller does *not* take ownership of the memory.
     */
    file_analysis::Analyzer* QueueAdd(const zeek::Tag& tag, RecordValPtr args);

    /**
     * Remove an analyzer from #file immediately.
     * @param tag the analyzer tag of the file analyzer to remove.
     * @param args an \c AnalyzerArgs value which specifies an analyzer.
     * @return false if analyzer didn't exist and so wasn't removed, else true.
     */
    bool Remove(const zeek::Tag& tag, RecordValPtr args);

    /**
     * Queue the removal of an analyzer from #file.
     * @param tag the analyzer tag of the file analyzer to remove.
     * @param args an \c AnalyzerArgs value which specifies an analyzer.
     * @return true if analyzer exists at time of call, else false;
     */
    bool QueueRemove(const zeek::Tag& tag, RecordValPtr args);

    /**
     * Perform all queued modifications to the current analyzer set.
     */
    void DrainModifications();

    // Iterator support
    using MapType = std::unordered_map<IntrusivePtr<ListVal>, file_analysis::Analyzer*, ListValHasher, ListValEqualTo>;
    using iterator = MapType::iterator;
    using const_iterator = MapType::const_iterator;
    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    iterator begin() { return analyzer_map.begin(); }
    iterator end() { return analyzer_map.end(); }
    const_iterator begin() const { return analyzer_map.begin(); }
    const_iterator end() const { return analyzer_map.end(); }
    const_iterator cbegin() { return analyzer_map.cbegin(); }
    const_iterator cend() { return analyzer_map.cend(); }

    size_t Size() const { return analyzer_map.size(); }

protected:
    /**
     * Create an instance of a file analyzer.
     * @param tag the tag of a file analyzer.
     * @param args an \c AnalyzerArgs value which specifies an analyzer.
     * @return a new file analyzer instance.
     */
    file_analysis::Analyzer* InstantiateAnalyzer(const zeek::Tag& tag, RecordValPtr args) const;

    /**
     * Insert an analyzer instance into the set.
     * @param a an analyzer instance.
     * @param key the hash key which represents the analyzer's \c AnalyzerArgs.
     */
    void Insert(file_analysis::Analyzer* a, const zeek::Tag& tag, RecordValPtr args);

    /**
     * Remove an analyzer instance from the set.
     * @param tag enumerator which specifies type of the analyzer to remove,
     *        just used for debugging messages.
     * @param key the hash key which represents the analyzer's \c AnalyzerArgs.
     */
    bool Remove(const zeek::Tag& tag, std::unique_ptr<zeek::detail::HashKey> key);

private:
    File* file; /**< File which owns the set */
    MapType analyzer_map;

    /**
     * Abstract base class for analyzer set modifications.
     */
    class Modification {
    public:
        Modification(zeek::Tag arg_tag, RecordValPtr arg_args) : tag(std::move(arg_tag)), args(std::move(arg_args)) {}
        virtual ~Modification() {}

        /**
         * Perform the modification on an analyzer set.
         * @param set the analyzer set on which the modification will happen.
         * @return true if the modification altered \a set.
         */
        virtual bool Perform(AnalyzerSet* set) = 0;

        /**
         * Don't perform the modification on the analyzer set and clean up.
         */
        virtual void Abort() = 0;

    protected:
        zeek::Tag tag;
        RecordValPtr args;
    };

    /**
     * Represents a request to add an analyzer to an analyzer set.
     */
    class AddMod final : public Modification {
    public:
        /**
         * Construct request which can add an analyzer to an analyzer set.
         * @param arg_a an analyzer instance to add to an analyzer set.
         * @param arg_key hash key representing the analyzer's \c AnalyzerArgs.
         */
        AddMod(file_analysis::Analyzer* arg_a, zeek::Tag arg_tag, RecordValPtr arg_args)
            : Modification(std::move(arg_tag), std::move(arg_args)), a(arg_a) {}
        ~AddMod() override = default;
        bool Perform(AnalyzerSet* set) override;
        void Abort() override;

    protected:
        file_analysis::Analyzer* a;
    };

    /**
     * Represents a request to remove an analyzer from an analyzer set.
     */
    class RemoveMod final : public Modification {
    public:
        /**
         * Construct request which can remove an analyzer from an analyzer set.
         * @param arg_a an analyzer instance to add to an analyzer set.
         * @param arg_key hash key representing the analyzer's \c AnalyzerArgs.
         */
        RemoveMod(zeek::Tag arg_tag, RecordValPtr arg_args) : Modification(std::move(arg_tag), std::move(arg_args)) {}
        ~RemoveMod() override = default;
        bool Perform(AnalyzerSet* set) override;
        void Abort() override {}
    };

    using ModQueue = std::queue<Modification*>;
    ModQueue mod_queue; /**< A queue of analyzer additions/removals requests. */
};

} // namespace detail
} // namespace file_analysis
} // namespace zeek
