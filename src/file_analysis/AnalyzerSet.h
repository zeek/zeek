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
 * A set of file analysis analyzers indexed by AnalyzerArgs.  Allows queueing
 * of addition/removals so that those modifications can happen at well-defined
 * times (e.g. to make sure a loop iterator isn't invalidated).
 */
class AnalyzerSet {
public:
	AnalyzerSet(File* arg_file);

	~AnalyzerSet();

	/**
	 * @return true if analyzer was instantiated/attached, else false.
	 */
	bool Add(RecordVal* args);

	/**
	 * @return true if analyzer was able to be instantiated, else false.
	 */
	bool QueueAdd(RecordVal* args);

	/**
	 * @return false if analyzer didn't exist and so wasn't removed, else true.
	 */
	bool Remove(const RecordVal* args);

	/**
	 * @return true if analyzer exists at time of call, else false;
	 */
	bool QueueRemove(const RecordVal* args);

	/**
	 * Perform all queued modifications to the currently active analyzers.
	 */
	void DrainModifications();

	IterCookie* InitForIteration() const
		{ return analyzer_map.InitForIteration(); }

	file_analysis::Analyzer* NextEntry(IterCookie* c)
		{ return analyzer_map.NextEntry(c); }

protected:
	HashKey* GetKey(const RecordVal* args) const;
	file_analysis::Analyzer* InstantiateAnalyzer(RecordVal* args) const;
	void Insert(file_analysis::Analyzer* a, HashKey* key);
	bool Remove(FA_Tag tag, HashKey* key);

private:
	File* file;
	CompositeHash* analyzer_hash;                /**< AnalyzerArgs hashes. */
	PDict(file_analysis::Analyzer) analyzer_map; /**< Indexed by AnalyzerArgs. */

	class Modification {
	public:
		virtual ~Modification() {}
		virtual bool Perform(AnalyzerSet* set) = 0;
		virtual void Abort() = 0;
	};

	class AddMod : public Modification {
	public:
		AddMod(file_analysis::Analyzer* arg_a, HashKey* arg_key)
			: Modification(), a(arg_a), key(arg_key) {}
		virtual ~AddMod() {}
		virtual bool Perform(AnalyzerSet* set);
		virtual void Abort() { delete a; delete key; }

	protected:
		file_analysis::Analyzer* a;
		HashKey* key;
	};

	class RemoveMod : public Modification {
	public:
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
	ModQueue mod_queue;
};

} // namespace file_analysiss

#endif
