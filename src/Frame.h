// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "BroList.h" // for typedef val_list
#include "Obj.h"

#include <unordered_map>
#include <string>
#include <utility>
#include <vector>

#include <broker/data.hh>
#include <broker/expected.hh>

namespace trigger { class Trigger; }
class CallExpr;
class BroFunc;

class Frame :  public BroObj {
public:
	/**
	 * Constructs a new frame belonging to *func* with *fn_args*
	 * arguments.
	 *
	 * @param the size of the frame
	 * @param func the function that is creating this frame
	 * @param fn_args the arguments being passed to that function.
	 */
	Frame(int size, const BroFunc* func, const val_list *fn_args);

	/**
	 * Deletes the frame. Unrefs its trigger, the values that it
	 * contains and its closure if applicable.
	 */
	virtual ~Frame() override;

	/**
	 * @param n the index to get.
	 * @return the value at index *n* of the underlying array.
	 */
	Val* NthElement(int n) const	{ return frame[n]; }

	/**
	 * Sets the element at index *n* of the underlying array
	 * to *v*.
	 *
	 * @param n the index to set
	 * @param v the value to set it to
	 * @param weak_ref whether the frame owns the value and should unref
	 * it upon destruction.  Used to break circular references between
	 * lambda functions and closure frames.
	 */
	void SetElement(int n, Val* v, bool weak_ref = false);

	/**
	 * Associates *id* and *v* in the frame. Future lookups of
	 * *id* will return *v*.
	 *
	 * @param id the ID to associate
	 * @param v the value to associate it with
	 */
	void SetElement(const ID* id, Val* v);

	/**
	 * Gets the value associated with *id* and returns it. Returns
	 * nullptr if no such element exists.
	 *
	 * @param id the id who's value to retreive
	 * @return the value associated with *id*
	 */
	Val* GetElement(const ID* id) const;

	/**
	 * Resets all of the indexes from [*startIdx, frame_size) in
	 * the Frame. Unrefs all of the values in reset indexes.
	 *
	 * @param the first index to unref.
	 */
	void Reset(int startIdx);

	/**
	 * Resets all of the values in the frame and clears out the
	 * underlying array.
	 */
	void Release();

	/**
	 * Describes the frame and all of its values.
	 */
	void Describe(ODesc* d) const override;

	/**
	 * @return the function that the frame is associated with.
	 */
	const BroFunc* GetFunction() const	{ return function; }

	/**
	 * @return the arguments passed to the function that this frame
	 * is associated with.
	 */
	const val_list* GetFuncArgs() const	{ return func_args; }

	/**
	 * Change the function that the frame is associated with.
	 *
	 * @param func the function for the frame to be associated with.
	 */
	void SetFunction(BroFunc* func)	{ function = func; }

	/**
	 * Sets the next statement to be executed in the context of the frame.
	 *
	 * @param stmt the statement to set it to.
	 */
	void SetNextStmt(Stmt* stmt)	{ next_stmt = stmt; }

	/**
	 * @return the next statement to be executed in the context of the frame.
	 */
	Stmt* GetNextStmt() const	{ return next_stmt; }

	/** Used to implement "next" command in debugger. */
	void BreakBeforeNextStmt(bool should_break)
		{ break_before_next_stmt = should_break; }
	bool BreakBeforeNextStmt() const
		{ return break_before_next_stmt; }

	/** Used to implement "finish" command in debugger. */
	void BreakOnReturn(bool should_break)
		{ break_on_return = should_break; }
	bool BreakOnReturn() const	{ return break_on_return; }

	/**
	 * Performs a deep copy of all the values in the current frame. If
	 * the frame has a closure the returned frame captures that closure
	 * by reference. As such, performing a clone operation does not copy
	 * the values in the closure.
	 *
	 * @return a copy of this frame.
	 */
	Frame* Clone() const;

	/**
	 * Clones a Frame, only making copies of the values associated with
	 * the IDs in selection. Cloning a frame does not deep-copy its
	 * closure; instead it makes a new copy of the frame which Refs the
	 * closure and all the elements that it might use from that closure.
	 *
	 * Unlike a regular clone operation where cloning the closure is quite
	 * hard because of circular references, cloning the closure here is
	 * possible. See Frame.cc for more notes on this.
	 *
	 * @return A copy of the frame where all the values associated with
	 * *selection* have been cloned. All other values are made to be
	 * null.
	 */
	Frame* SelectiveClone(const id_list& selection, BroFunc* func) const;

	/**
	 * Serializes the Frame into a Broker representation.
	 *
	 * Serializing a frame can be fairly non-trivial. If the frame has no
	 * closure the serialized frame is just a vector:
	 *
	 * [ "Frame", [offset_map] [serialized_values] ]
	 *
	 * Where serialized_values are two element vectors. A serialized_value
	 * has the result of calling broker::data_to_val on the value in the
	 * first index, and an integer representing that value's type in the
	 * second index. offset_map is a serialized version of the frame's
	 * offset_map.
	 *
	 * A Frame with a closure needs to serialize a little more information.
	 * It is serialized as:
	 *
	 * [ "ClosureFrame", [outer_ids], Serialize(closure), [offset_map],
	 *   [serialized_values] ]
	 *
	 * @return the broker representaton, or an error if the serialization
	 * failed.
	 */
	static broker::expected<broker::data> Serialize(const Frame* target, const id_list& selection);

	/**
	 * Instantiates a Frame from a serialized one.
	 *
	 * @return a pair in which the first item is the status of the serialization;
	 * and the second is the unserialized frame with reference count +1, or
	 * null if the serialization wasn't successful.
	 */
	static std::pair<bool, Frame*> Unserialize(const broker::vector& data);

	/**
	 * Sets the IDs that the frame knows offsets for. These offsets will
	 * be used instead of any previously provided ones for future lookups
	 * of IDs in *ids*.
	 *
	 * @param ids the ids that the frame will intake.
	 */
	void AddKnownOffsets(const id_list& ids);

	/**
	 * Captures *c* as this frame's closure and Refs all of the values
	 * corresponding to outer_ids in that closure. This also Refs *c* as
	 * the frame will unref it upon deconstruction. When calling this,
	 * the frame's closure must not have been set yet.
	 */
	void CaptureClosure(Frame* c, id_list outer_ids);

	// If the frame is run in the context of a trigger condition evaluation,
	// the trigger needs to be registered.
	void SetTrigger(trigger::Trigger* arg_trigger);
	void ClearTrigger();
	trigger::Trigger* GetTrigger() const		{ return trigger; }

	void SetCall(const CallExpr* arg_call)	{ call = arg_call; }
	void ClearCall()			{ call = 0; }
	const CallExpr* GetCall() const		{ return call; }

	void SetDelayed()	{ delayed = true; }
	bool HasDelayed() const	{ return delayed; }

	/**
	 * Track a new function that refers to this frame for use as a closure.
	 * This frame's destructor will then upgrade that functions reference
	 * from weak to strong (by making a copy).  The initial use of
	 * weak references prevents unbreakable circular references that
	 * otherwise cause memory leaks.
	 */
	void AddFunctionWithClosureRef(BroFunc* func);

private:

	/**
	 * Unrefs the value at offset 'n' frame unless it's a weak reference.
	 */
	void UnrefElement(int n);

	/** Have we captured this id? */
	bool IsOuterID(const ID* in) const;

	/** Serializes an offset_map */
	static broker::expected<broker::data>
	SerializeOffsetMap(const std::unordered_map<std::string, int>& in);

	/** Serializes an id_list */
	static broker::expected<broker::data>
	SerializeIDList(const id_list& in);

	/** Unserializes an offset map. */
	static std::pair<bool, std::unordered_map<std::string, int>>
	UnserializeOffsetMap(const broker::vector& data);

	/** Unserializes an id_list. */
	static std::pair<bool, id_list>
	UnserializeIDList(const broker::vector& data);

	/** The number of vals that can be stored in this frame. */
	int size;

	/** Associates ID's offsets with values. */
	Val** frame;

	/** Values that are weakly referenced by the frame.  Used to
	 * prevent circular reference memory leaks in lambda/closures */
	bool* weak_refs = nullptr;

	/** The enclosing frame of this frame. */
	Frame* closure;
	bool weak_closure_ref = false;

	/** ID's used in this frame from the enclosing frame. */
	id_list outer_ids;

	/**
	 * Maps ID names to offsets. Used if this frame is  serialized
	 * to maintain proper offsets after being sent elsewhere.
	 */
	std::unordered_map<std::string, int> offset_map;

	/** The function this frame is associated with. */
	const BroFunc* function;
	/** The arguments to the function that this Frame is associated with. */
	const val_list* func_args;

	/** The next statement to be evaluted in the context of this frame. */
	Stmt* next_stmt;

	bool break_before_next_stmt;
	bool break_on_return;

	trigger::Trigger* trigger;
	const CallExpr* call;
	bool delayed;

	std::vector<BroFunc*> functions_with_closure_frame_reference;
};

/**
 * If we stopped using this and instead just made a struct of the information
 * that the debugger actually uses we could make the Frame a class a template.
 * The template argument could be <int frame_size> and doing this would allow
 * us to use an std::array under the hood rather than a c style array.
 *
 * Another way to do this might to be to have Frame inherit from a class
 * DebugFrame which provides the information that the debugger uses. See:
 * https://stackoverflow.com/a/16211097
 */
extern std::vector<Frame*> g_frame_stack;
