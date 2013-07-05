// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_ANALYZERSET_H
#define FILE_ANALYSIS_ANALYZERSET_H

#include <queue>

#include "Analyzer.h"
#include "Dict.h"
#include "CompHash.h"
#include "Val.h"

namespace file_analysis {

class File;
declare(PDict,Analyzer);

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
	AnalyzerSet(File* arg_file);

	/**
	 * Destructor.  Any queued analyzer additions/removals are aborted and
	 * will not occur.
	 */
	~AnalyzerSet();

	/**
	 * Attach an analyzer to #file immediately.
	 * @param args an \c AnalyzerArgs value which specifies an analyzer.
	 * @return true if analyzer was instantiated/attached, else false.
	 */
	bool Add(RecordVal* args);

	/**
	 * Queue the attachment of an analyzer to #file.
	 * @param args an \c AnalyzerArgs value which specifies an analyzer.
	 * @return true if analyzer was able to be instantiated, else false.
	 */
	bool QueueAdd(RecordVal* args);

	/**
	 * Remove an analyzer from #file immediately.
	 * @param args an \c AnalyzerArgs value which specifies an analyzer.
	 * @return false if analyzer didn't exist and so wasn't removed, else true.
	 */
	bool Remove(const RecordVal* args);

	/**
	 * Queue the removal of an analyzer from #file.
	 * @param args an \c AnalyzerArgs value which specifies an analyzer.
	 * @return true if analyzer exists at time of call, else false;
	 */
	bool QueueRemove(const RecordVal* args);

	/**
	 * Perform all queued modifications to the current analyzer set.
	 */
	void DrainModifications();

	/**
	 * Prepare the analyzer set to be iterated over.
	 * @see Dictionary#InitForIteration
	 * @return an iterator that may be used to loop over analyzers in the set.
	 */
	IterCookie* InitForIteration() const
		{ return analyzer_map.InitForIteration(); }

	/**
	 * Get next entry in the analyzer set.
	 * @see Dictionary#NextEntry
	 * @param c a set iterator.
	 * @return the next analyzer in the set or a null pointer if there is no
	 *         more left (in that case the cookie is also deleted).
	 */
	file_analysis::Analyzer* NextEntry(IterCookie* c)
		{ return analyzer_map.NextEntry(c); }

protected:

	/**
	 * Get a hash key which represents an analyzer instance.
	 * @param args an \c AnalyzerArgs value which specifies an analyzer.
	 * @return the hash key calculated from \a args
	 */
	HashKey* GetKey(const RecordVal* args) const;

	/**
	 * Create an instance of a file analyzer.
	 * @param args an \c AnalyzerArgs value which specifies an analyzer.
	 * @return a new file analyzer instance.
	 */
	file_analysis::Analyzer* InstantiateAnalyzer(RecordVal* args) const;

	/**
	 * Insert an analyzer instance in to the set.
	 * @param a an analyzer instance.
	 * @param key the hash key which represents the analyzer's \c AnalyzerArgs.
	 */
	void Insert(file_analysis::Analyzer* a, HashKey* key);

	/**
	 * Remove an analyzer instance from the set.
	 * @param tag enumarator which specifies type of the analyzer to remove,
	 *        just used for debugging messages.
	 * @param key the hash key which represents the analyzer's \c AnalyzerArgs.
	 */
	bool Remove(FA_Tag tag, HashKey* key);

private:

	File* file;                                  /**< File which owns the set */
	CompositeHash* analyzer_hash;                /**< AnalyzerArgs hashes. */
	PDict(file_analysis::Analyzer) analyzer_map; /**< Indexed by AnalyzerArgs. */

	/**
	 * Abstract base class for analyzer set modifications.
	 */
	class Modification {
	public:
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
	};

	/**
	 * Represents a request to add an analyzer to an analyzer set.
	 */
	class AddMod : public Modification {
	public:
		/**
		 * Construct request which can add an analyzer to an analyzer set.
		 * @param arg_a an analyzer instance to add to an analyzer set.
		 * @param arg_key hash key representing the analyzer's \c AnalyzerArgs.
		 */
		AddMod(file_analysis::Analyzer* arg_a, HashKey* arg_key)
			: Modification(), a(arg_a), key(arg_key) {}
		virtual ~AddMod() {}
		virtual bool Perform(AnalyzerSet* set);
		virtual void Abort() { delete a; delete key; }

	protected:
		file_analysis::Analyzer* a;
		HashKey* key;
	};

	/**
	 * Represents a request to remove an analyzer from an analyzer set.
	 */
	class RemoveMod : public Modification {
	public:
		/**
		 * Construct request which can remove an analyzer from an analyzer set.
		 * @param arg_a an analyzer instance to add to an analyzer set.
		 * @param arg_key hash key representing the analyzer's \c AnalyzerArgs.
		 */
		RemoveMod(FA_Tag arg_tag, HashKey* arg_key)
			: Modification(), tag(arg_tag), key(arg_key) {}
		virtual ~RemoveMod() {}
		virtual bool Perform(AnalyzerSet* set);
		virtual void Abort() { delete key; }

	protected:
		FA_Tag tag;
		HashKey* key;
	};

	typedef queue<Modification*> ModQueue;
	ModQueue mod_queue;	/**< A queue of analyzer additions/removals requests. */
};

} // namespace file_analysiss

#endif
