// See the file "COPYING" in the main distribution directory for copyright.

#ifndef frame_h
#define frame_h

#include <vector>
#include <unordered_map>
#include <string>
#include <memory> // std::shared_ptr
#include <utility> // std::pair

#include <broker/data.hh>
#include <broker/expected.hh>

#include "Val.h"

class BroFunc;
class Trigger;
class CallExpr;
class Val;

class Frame : public BroObj {
friend class BroFunc;
public:
	Frame(int size, const BroFunc* func, const val_list *fn_args);
	// Constructs a copy or view of other. If a view is constructed the
	// destructor will not change other's state on deletion.
	Frame(const Frame* other, bool is_view = false);
	~Frame() override;

	Val* NthElement(int n) const { return frame[n]; }
	void SetElement(int n, Val* v);
	virtual void SetElement(const ID* id, Val* v);

	virtual Val* GetElement(const ID* id) const;
	void AddElement(ID* id, Val* v);

	void Reset(int startIdx);
	void Release();

	void Describe(ODesc* d) const override;

	// For which function is this stack frame.
	const BroFunc* GetFunction() const	{ return function; }
	const val_list* GetFuncArgs() const	{ return func_args; }

	// Next statement to be executed in the context of this frame.
	void SetNextStmt(Stmt* stmt)	{ next_stmt = stmt; }
	Stmt* GetNextStmt() const	{ return next_stmt; }

	// Used to implement "next" command in debugger.
	void BreakBeforeNextStmt(bool should_break)
		{ break_before_next_stmt = should_break; }
	bool BreakBeforeNextStmt() const
		{ return break_before_next_stmt; }

	// Used to implement "finish" command in debugger.
	void BreakOnReturn(bool should_break)
		{ break_on_return = should_break; }
	bool BreakOnReturn() const	{ return break_on_return; }

	// Deep-copies values.
	virtual Frame* Clone();

	/**
	 * Clones this frame, only copying values corresponding to IDs in
	 * *selection*. All other values are null.
	 *
	 * @param selection a list of IDs that will be cloned into the new
	 * frame.
	 * @return a new frame with the requested values and ref count +1
	 */
	virtual Frame* SelectiveClone(id_list* selection);

	/**
	 * Serializes the Frame into a Broker representation.
	 *
	 * @return the broker representaton, or an error if the serialization
	 * failed.
	*/
	virtual broker::expected<broker::data> Serialize() const;

	/**
	 * Instantiates a Frame from a serialized one.
	 *
	 * @return a pair. the first item is the status of the serialization,
	 * the second is the Unserialized frame with reference count +1
	 */
	static std::pair<bool, Frame*> Unserialize(const broker::vector& data);

	/**
	 * Installs *outer_ids* in this Frame's offset_map. 
	 * 
	 * Note: This needs to be done before serializing a Frame to guarantee that 
	 * the unserialized frame will perform lookups properly.
	 * 
	 * @param outer_ids the ids that this frame holds
	 */
	void SetOuterIDs(std::shared_ptr<id_list> outer_ids);

	/**
	 * @return does this frame have an initialized offset_map?
	 */
	bool HasOuterIDs() const { return offset_map.size(); }

	// If the frame is run in the context of a trigger condition evaluation,
	// the trigger needs to be registered.
	void SetTrigger(Trigger* arg_trigger);
	void ClearTrigger();
	Trigger* GetTrigger() const		{ return trigger; }

	void SetCall(const CallExpr* arg_call)	{ call = arg_call; }
	void ClearCall()			{ call = 0; }
	const CallExpr* GetCall() const		{ return call; }

	void SetDelayed()	{ delayed = true; }
	bool HasDelayed() const	{ return delayed; }

protected:
	void Clear();

	/**
	 * Does offset_map contain an offset corresponding to *i*?
	 *
	 * @param i the ID to check for.
	 * @return true of offset_map has an offset for i, false otherwise.
	 */
	bool CaptureContains(const ID* i) const;

	/**
	 * Serializes this Frame's offset map.
	 * 
	 * @return a serialized version of the offset map.
	 */
	broker::expected<broker::data> SerializeOffsetMap() const;

	Val** frame;
	int size;

	const BroFunc* function;
	const val_list* func_args;
	Stmt* next_stmt;

	bool break_before_next_stmt;
	bool break_on_return;

	Trigger* trigger;
	const CallExpr* call;
	bool delayed;

	/** 
	 * Maps ID names to the offsets they had when passed into the frame.
	 * 
	 * A frame that has been serialized maintains its own map between IDs and
	 * their offsets. This is because a serialized frame is not guaranteed to 
	 * be unserialized somewhere where the offsets for the IDs that it contains
	 * are the same.
	 */
	std::unordered_map<std::string, int> offset_map;

private:

	/** 
	 * Rather or not this frame is a view of another one. Frames that
	 * are views do not delete their underlying frame on deletion.
	 */
	bool is_view;
};


/**
 * Class that allows for actions in both a regular frame and a closure frame
 * according to a list of outer IDs captured in the closure passed into the
 * constructor. 
 */
class ClosureFrame : public Frame {
public:
	/**
	 * Constructs a closure Frame from a closure and body frame, and a list of ids
	 * that this frame should refer to its closure to for values. For non closure
	 * related operations the ClosureFrame is just a view of the body frame.
	 *
	 * @param closure the frame that holds IDs in *outer_ids*.
	 * @param body the frame to refer to for all non-closure actions.
	 * @param outer_ids a list of ids that have been captured by the ClosureFrame.
	 * These inform the closure on where to refer get and set operations.
	 */
	ClosureFrame(Frame* closure, Frame* body, std::shared_ptr<id_list> outer_ids);
	~ClosureFrame() override;

	Val* GetElement(const ID* id) const override;
	void SetElement(const ID* id, Val* v) override;

	Frame* Clone() override;
	Frame* SelectiveClone(id_list* selection) override;

	broker::expected<broker::data> Serialize() const override;
	static bool UnserializeIntoOffsetMap
		(const broker::vector& data, std::unordered_map<std::string, int>& target);

private:

	/**
	 * Finds the Value corresponding to *id* in the closure of *start*.
	 * 
	 * @param start the frame to begin the search from
	 * @param id the ID whose corresponding value is to be collected.
	 * @param offset the offset at which to look for id's value when its
	 * frame has been found.
	 * @return the Value corresponding to *id*.
	 */
	static Val* GatherFromClosure(const Frame* start, const ID* id, const int offset);

	/**
	 * Sets the Value corresponding to *id* in the closure of *start* to *val*
	 *
	 * @param start the frame to begin the search from
	 * @param val the Value to associate with *id* in the closure.
	 * @param id the ID whose corresponding value is to be updated.
	 * @param offset the offset at which to look for id's value when its
	 * frame has been found.
	 */
	static void SetInClosure(Frame* start, const ID* id, Val* val, const int offset);

	Frame* closure;
	Frame* body;
};

extern std::vector<Frame*> g_frame_stack;

#endif
