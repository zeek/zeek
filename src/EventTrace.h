// Classes for tracing/dumping Zeek events.

#pragma once

#include "zeek/Val.h"
#include "zeek/ZeekArgs.h"

namespace zeek::detail
	{

class ValTrace;
class ValTraceMgr;

// Abstract class for capturing a single difference between two script-level
// values.  Includes notions of inserting, changing, or deleting a value.
class ValDelta
	{
public:
	ValDelta(const ValTrace* _vt) : vt(_vt) { }
	virtual ~ValDelta() { }

	// Return a string that performs the update operation, expressed
	// as Zeek scripting.  Does not include a terminating semicolon.
	virtual std::string Generate(ValTraceMgr* vtm) const;

	// Whether the generated string needs the affected value to
	// explicitly appear on the left-hand-side.  Note that this
	// might not be as a simple "LHS = RHS" assignment, but instead
	// as "LHS$field = RHS" or "LHS[index] = RHS".
	//
	// Returns false for generated strings like "delete LHS[index]".
	virtual bool NeedsLHS() const { return true; }

	const ValTrace* GetValTrace() const { return vt; }

protected:
	const ValTrace* vt;
	};

using DeltaVector = std::vector<std::unique_ptr<ValDelta>>;

// Tracks the elements of a value as seen at a given point in execution.
// For non-aggregates, this is simply the Val object, but for aggregates
// it is (recursively) each of the sub-elements, in a manner that can then
// be readily compared against future instances.
class ValTrace
	{
public:
	ValTrace(const ValPtr& v);
	~ValTrace();

	const ValPtr& GetVal() const { return v; }
	const TypePtr& GetType() const { return t; }
	const auto& GetElems() const { return elems; }

	// Returns true if this trace and the given one represent the
	// same underlying value.  Can involve subelement-by-subelement
	// (recursive) comparisons.
	bool operator==(const ValTrace& vt) const;
	bool operator!=(const ValTrace& vt) const { return ! ((*this) == vt); }

	// Computes the deltas between a previous ValTrace and this one.
	// If "prev" is nil then we're creating this value from scratch
	// (though if it's an aggregate, we may reuse existing values
	// for some of its components).
	//
	// Returns the accumulated differences in "deltas".  If on return
	// nothing was added to "deltas" then the two ValTrace's are equivalent
	// (no changes between them).
	void ComputeDelta(const ValTrace* prev, DeltaVector& deltas) const;

private:
	// Methods for tracing different types of aggregate values.
	void TraceList(const ListValPtr& lv);
	void TraceRecord(const RecordValPtr& rv);
	void TraceTable(const TableValPtr& tv);
	void TraceVector(const VectorValPtr& vv);

	// Predicates for comparing different types of aggregates for equality.
	bool SameList(const ValTrace& vt) const;
	bool SameRecord(const ValTrace& vt) const;
	bool SameTable(const ValTrace& vt) const;
	bool SameVector(const ValTrace& vt) const;

	// Helper function that knows about the internal vector-of-subelements
	// we use for aggregates.
	bool SameElems(const ValTrace& vt) const;

	// True if this value is a singleton and it's the same value as
	// represented in "vt".
	bool SameSingleton(const ValTrace& vt) const;

	// Add to "deltas" the differences needed to turn a previous instance
	// of the given type of aggregate to the current instance.
	void ComputeRecordDelta(const ValTrace* prev, DeltaVector& deltas) const;
	void ComputeTableDelta(const ValTrace* prev, DeltaVector& deltas) const;
	void ComputeVectorDelta(const ValTrace* prev, DeltaVector& deltas) const;

	// Holds sub-elements for aggregates.
	std::vector<std::shared_ptr<ValTrace>> elems;

	// A parallel vector used for the yield values of tables.
	std::vector<std::shared_ptr<ValTrace>> elems2;

	ValPtr v;
	TypePtr t; // v's type, for convenience
	};

// Captures the basic notion of a new, non-equivalent value being assigned.
class DeltaReplaceValue : public ValDelta
	{
public:
	DeltaReplaceValue(const ValTrace* _vt, ValPtr _new_val)
		: ValDelta(_vt), new_val(std::move(_new_val))
		{
		}

	std::string Generate(ValTraceMgr* vtm) const override;

private:
	ValPtr new_val;
	};

// Captures the notion of setting a record field.
class DeltaSetField : public ValDelta
	{
public:
	DeltaSetField(const ValTrace* _vt, int _field, ValPtr _new_val)
		: ValDelta(_vt), field(_field), new_val(std::move(_new_val))
		{
		}

	std::string Generate(ValTraceMgr* vtm) const override;

private:
	int field;
	ValPtr new_val;
	};

// Captures the notion of deleting a record field.
class DeltaRemoveField : public ValDelta
	{
public:
	DeltaRemoveField(const ValTrace* _vt, int _field) : ValDelta(_vt), field(_field) { }

	std::string Generate(ValTraceMgr* vtm) const override;
	bool NeedsLHS() const override { return false; }

private:
	int field;
	};

// Captures the notion of creating a record from scratch.
class DeltaRecordCreate : public ValDelta
	{
public:
	DeltaRecordCreate(const ValTrace* _vt) : ValDelta(_vt) { }

	std::string Generate(ValTraceMgr* vtm) const override;
	};

// Captures the notion of adding an element to a set.  Use DeltaRemoveTableEntry to
// delete values.
class DeltaSetSetEntry : public ValDelta
	{
public:
	DeltaSetSetEntry(const ValTrace* _vt, ValPtr _index) : ValDelta(_vt), index(_index) { }

	std::string Generate(ValTraceMgr* vtm) const override;
	bool NeedsLHS() const override { return false; }

private:
	ValPtr index;
	};

// Captures the notion of setting a table entry (which includes both changing
// an existing one and adding a new one).  Use DeltaRemoveTableEntry to
// delete values.
class DeltaSetTableEntry : public ValDelta
	{
public:
	DeltaSetTableEntry(const ValTrace* _vt, ValPtr _index, ValPtr _new_val)
		: ValDelta(_vt), index(_index), new_val(std::move(_new_val))
		{
		}

	std::string Generate(ValTraceMgr* vtm) const override;

private:
	ValPtr index;
	ValPtr new_val;
	};

// Captures the notion of removing a table/set entry.
class DeltaRemoveTableEntry : public ValDelta
	{
public:
	DeltaRemoveTableEntry(const ValTrace* _vt, ValPtr _index)
		: ValDelta(_vt), index(std::move(_index))
		{
		}

	std::string Generate(ValTraceMgr* vtm) const override;
	bool NeedsLHS() const override { return false; }

private:
	ValPtr index;
	};

// Captures the notion of creating a set from scratch.
class DeltaSetCreate : public ValDelta
	{
public:
	DeltaSetCreate(const ValTrace* _vt) : ValDelta(_vt) { }

	std::string Generate(ValTraceMgr* vtm) const override;
	};

// Captures the notion of creating a table from scratch.
class DeltaTableCreate : public ValDelta
	{
public:
	DeltaTableCreate(const ValTrace* _vt) : ValDelta(_vt) { }

	std::string Generate(ValTraceMgr* vtm) const override;
	};

// Captures the notion of changing an element of a vector.
class DeltaVectorSet : public ValDelta
	{
public:
	DeltaVectorSet(const ValTrace* _vt, int _index, ValPtr _elem)
		: ValDelta(_vt), index(_index), elem(std::move(_elem))
		{
		}

	std::string Generate(ValTraceMgr* vtm) const override;

private:
	int index;
	ValPtr elem;
	};

// Captures the notion of adding an entry to the end of a vector.
class DeltaVectorAppend : public ValDelta
	{
public:
	DeltaVectorAppend(const ValTrace* _vt, int _index, ValPtr _elem)
		: ValDelta(_vt), index(_index), elem(std::move(_elem))
		{
		}

	std::string Generate(ValTraceMgr* vtm) const override;

private:
	int index;
	ValPtr elem;
	};

// Captures the notion of replacing a vector wholesale.
class DeltaVectorCreate : public ValDelta
	{
public:
	DeltaVectorCreate(const ValTrace* _vt) : ValDelta(_vt) { }

	std::string Generate(ValTraceMgr* vtm) const override;
	};

// Captures the notion of creating a value with an unsupported type
// (like "opaque").
class DeltaUnsupportedCreate : public ValDelta
	{
public:
	DeltaUnsupportedCreate(const ValTrace* _vt) : ValDelta(_vt) { }

	std::string Generate(ValTraceMgr* vtm) const override;
	};

// Manages the changes to (or creation of) a variable used to represent
// a value.
class DeltaGen
	{
public:
	DeltaGen(ValPtr _val, std::string _rhs, bool _needs_lhs, bool _is_first_def)
		: val(std::move(_val)), rhs(std::move(_rhs)), needs_lhs(_needs_lhs),
		  is_first_def(_is_first_def)
		{
		}

	const ValPtr& GetVal() const { return val; }
	const std::string& RHS() const { return rhs; }
	bool NeedsLHS() const { return needs_lhs; }
	bool IsFirstDef() const { return is_first_def; }

private:
	ValPtr val;

	// The expression to set the variable to.
	std::string rhs;

	// Whether that expression needs the variable explicitly provides
	// on the lefthand side.
	bool needs_lhs;

	// Whether this is the first definition of the variable (in which
	// case we also need to declare the variable).
	bool is_first_def;
	};

using DeltaGenVec = std::vector<DeltaGen>;

// Tracks a single event.
class EventTrace
	{
public:
	// Constructed in terms of the associated script function, "network
	// time" when the event occurred, and the position of this event
	// within all of those being traced.
	EventTrace(const ScriptFunc* _ev, double _nt, size_t event_num);

	// Sets a string representation of the arguments (values) being
	// passed to the event.
	void SetArgs(std::string _args) { args = std::move(_args); }

	// Adds to the trace an update for the given value.
	void AddDelta(ValPtr val, std::string rhs, bool needs_lhs, bool is_first_def)
		{
		auto& d = is_post ? post_deltas : deltas;
		d.emplace_back(DeltaGen(val, rhs, needs_lhs, is_first_def));
		}

	// Initially we analyze events pre-execution.  When this flag
	// is set, we switch to instead analyzing post-execution.  The
	// difference allows us to annotate the output with "# from script"
	// comments that flag changes created by script execution rather
	// than event engine activity.
	void SetDoingPost() { is_post = true; }

	const char* GetName() const { return name.c_str(); }

	// Generates an internal event handler that sets up the values
	// associated with the traced event, followed by queueing the traced
	// event, and then queueing the successor internal event handler,
	// if any.
	//
	// "predecessor", if non-nil, gives the event that came just before
	// this one (used for "# from script" annotations").  "successor",
	// if not empty, gives the name of the successor internal event.
	void Generate(FILE* f, ValTraceMgr& vtm, const EventTrace* predecessor,
	              std::string successor) const;

private:
	// "dvec" is either just our deltas, or the "post_deltas" of our
	// predecessor plus our deltas.
	void Generate(FILE* f, ValTraceMgr& vtm, const DeltaGenVec& dvec, std::string successor,
	              int num_pre = 0) const;

	const ScriptFunc* ev;
	double nt;
	bool is_post = false;

	// The deltas needed to construct the values associated with this
	// event prior to its execution.
	DeltaGenVec deltas;

	// The deltas capturing any changes to the original values as induced
	// by executing its event handlers.
	DeltaGenVec post_deltas;

	// The event's name and a string representation of its arguments.
	std::string name;
	std::string args;
	};

// Manages all of the events and associated values seen during the execution.
class ValTraceMgr
	{
public:
	// Invoked to trace a new event with the associated arguments.
	void TraceEventValues(std::shared_ptr<EventTrace> et, const zeek::Args* args);

	// Invoked when the current event finishes execution.  The arguments
	// are again provided, for convenience so we don't have to remember
	// them from the previous method.
	void FinishCurrentEvent(const zeek::Args* args);

	// Returns the name of the script variable associated with the
	// given value.
	const std::string& ValName(const ValPtr& v);
	const std::string& ValName(const ValTrace* vt) { return ValName(vt->GetVal()); }

	// Returns true if the script variable associated with the given value
	// needs to be global (because it's used across multiple events).
	bool IsGlobal(const ValPtr& v) const { return globals.count(v.get()) > 0; }

	// Returns or sets the "base time" from which eligible times are
	// transformed into offsets rather than maintained as absolute
	// values.
	double GetBaseTime() const { return base_time; }
	void SetBaseTime(double bt) { base_time = bt; }

	// Returns a Zeek script representation of the given "time" value.
	// This might be relative to base_time or might be absolute.
	std::string TimeConstant(double t);

	// Returns the array of per-type-tag constants.
	const auto& GetConstants() const { return constants; }

private:
	// Traces the given value, which we may-or-may-not have seen before.
	void AddVal(ValPtr v);

	// Creates a new value, associating a script variable with it.
	void NewVal(ValPtr v);

	// Called when the given value is used in an expression that sets
	// or updates another value.  This lets us track which values are
	// used across multiple events, and thus need to be global.
	void ValUsed(const ValPtr& v);

	// Compares the two value traces to build up deltas capturing
	// the difference between the previous one and the current one.
	void AssessChange(const ValTrace* vt, const ValTrace* prev_vt);

	// Create and track a script variable associated with the given value.
	void TrackVar(const Val* vt);

	// Generates a name for a value.
	std::string GenValName(const ValPtr& v);

	// True if the given value is an unspecified (and empty set,
	// table, or vector appearing as a constant rather than an
	// already-typed value).
	bool IsUnspecifiedAggregate(const ValPtr& v) const;

	// True if the given value has an unsupported type.
	bool IsUnsupported(const Val* v) const;

	// Maps values to their associated traces.
	std::unordered_map<const Val*, std::shared_ptr<ValTrace>> val_map;

	// Maps values to the "names" we associated with them.  For simple
	// values, the name is just a Zeek script constant.  For aggregates,
	// it's a dedicated script variable.
	std::unordered_map<const Val*, std::string> val_names;
	int num_vars = 0; // the number of dedicated script variables

	// Tracks which values we've processed up through the preceding event.
	// Any re-use we then see for the current event (via a ValUsed() call)
	// then tells us that the value is used across events, and thus its
	// associated script variable needs to be global.
	std::unordered_set<const Val*> processed_vals;

	// Tracks which values have associated script variables that need
	// to be global.
	std::unordered_set<const Val*> globals;

	// Indexed by type tag, stores an ordered set of all of the distinct
	// representations of constants of that type.
	std::array<std::set<std::string>, NUM_TYPES> constants;

	// If non-zero, then we've established a "base time" and will report
	// time constants as offsets from it (when reasonable, i.e., no
	// negative offsets, and base_time can't be too close to 0.0).
	double base_time = 0.0;

	// The event we're currently tracing.
	std::shared_ptr<EventTrace> curr_ev;

	// Hang on to values we're tracking to make sure the pointers don't
	// get reused when the main use of the value ends.
	std::vector<ValPtr> vals;
	};

// Manages tracing of all of the events seen during execution, including
// the final generation of the trace script.
class EventTraceMgr
	{
public:
	EventTraceMgr(const std::string& trace_file);
	~EventTraceMgr();

	// Called at the beginning of invoking an event's handlers.
	void StartEvent(const ScriptFunc* ev, const zeek::Args* args);

	// Called after finishing with invoking an event's handlers.
	void EndEvent(const ScriptFunc* ev, const zeek::Args* args);

	// Used to track events generated at script-level.
	void ScriptEventQueued(const EventHandlerPtr& h);

private:
	FILE* f = nullptr;
	ValTraceMgr vtm;

	// All of the events we've traced so far.
	std::vector<std::shared_ptr<EventTrace>> events;

	// The names of all of the script events that have been generated.
	std::unordered_set<std::string> script_events;
	};

// If non-nil then we're doing event tracing.
extern std::unique_ptr<EventTraceMgr> etm;

	} // namespace zeek::detail
