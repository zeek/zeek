// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <unordered_map>
#include <string>
#include <utility>
#include <vector>
#include <memory>
#include <optional>

#include <broker/data.hh>
#include <broker/expected.hh>

#include "zeek/ZeekList.h" // for typedef val_list
#include "zeek/Obj.h"
#include "zeek/Type.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/ZeekArgs.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(CallExpr, zeek::detail);
ZEEK_FORWARD_DECLARE_NAMESPACED(Trigger, zeek::detail::trigger);

namespace zeek {
using ValPtr = IntrusivePtr<Val>;

namespace detail {
class ScriptFunc;
using IDPtr = IntrusivePtr<ID>;

namespace trigger {
using TriggerPtr = IntrusivePtr<Trigger>;
}

class Frame;
using FramePtr = IntrusivePtr<Frame>;

class Frame :  public Obj {
public:
	/**
	 * Constructs a new frame belonging to *func* with *fn_args*
	 * arguments.
	 *
	 * @param the size of the frame
	 * @param func the function that is creating this frame
	 * @param fn_args the arguments being passed to that function.
	 */
	Frame(int size, const ScriptFunc* func, const zeek::Args* fn_args);

	/**
	 * Deletes the frame. Unrefs its trigger, the values that it
	 * contains and its closure if applicable.
	 */
	virtual ~Frame() override;

	/**
	 * @param n the index to get.
	 * @return the value at index *n* of the underlying array.
	 */
	const ValPtr& GetElement(int n) const
		{
		// Note: technically this may want to adjust by current_offset, but
		// in practice, this method is never called from anywhere other than
		// function call invocation, where current_offset should be zero.
		return frame[n].val;
		}

	/**
	 * Sets the element at index *n* of the underlying array to *v*.
	 * @param n the index to set
	 * @param v the value to set it to
	 */
	void SetElement(int n, ValPtr v);

	/**
	 * Associates *id* and *v* in the frame. Future lookups of
	 * *id* will return *v*.
	 *
	 * @param id the ID to associate
	 * @param v the value to associate it with
	 */
	void SetElement(const ID* id, ValPtr v);
	void SetElement(const IDPtr& id, ValPtr v)
		{ SetElement(id.get(), std::move(v)); }

	/**
	 * Gets the value associated with *id* and returns it. Returns
	 * nullptr if no such element exists.
	 *
	 * @param id the id who's value to retreive
	 * @return the value associated with *id*
	 */
	const ValPtr& GetElementByID(const IDPtr& id) const
		{ return GetElementByID(id.get()); }

	/**
	 * Adjusts the current offset being used for frame accesses.
	 * This is in support of inlined functions.
	 *
	 * @param incr  Amount by which to increase the frame offset.
	 *              Use a negative value to shrink the offset.
	 */
	void AdjustOffset(int incr)   { current_offset += incr; }

	/**
	 * Resets all of the indexes from [*startIdx, frame_size) in
	 * the Frame.
	 * @param the first index to unref.
	 */
	void Reset(int startIdx);

	/**
	 * Describes the frame and all of its values.
	 */
	void Describe(ODesc* d) const override;

	/**
	 * @return the function that the frame is associated with.
	 */
	const ScriptFunc* GetFunction() const	{ return function; }

	/**
	 * @return the arguments passed to the function that this frame
	 * is associated with.
	 */
	const Args* GetFuncArgs() const	{ return func_args; }

	/**
	 * Change the function that the frame is associated with.
	 *
	 * @param func the function for the frame to be associated with.
	 */
	void SetFunction(ScriptFunc* func)	{ function = func; }

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
	Frame* SelectiveClone(const IDPList& selection, ScriptFunc* func) const;

	/**
	 * Serializes the frame in the context of supporting the (deprecated)
	 * reference semantics for closures.  This can be fairly non-trivial.
	 * If the frame itself has no closure then the serialized frame
	 * is a vector:
	 *
	 * [ "Frame", [offset_map] [serialized_values] ]
	 *
	 * where serialized_values are two-element vectors. A serialized_value
	 * has the result of calling broker::data_to_val on the value in the
	 * first index, and an integer representing that value's type in the
	 * second index. offset_map is a serialized version of the frame's
	 * offset_map.
	 *
	 * A reference-semantics frame with its own closure needs to
	 * (recursively) serialize more information:
	 *
	 * [ "ClosureFrame", [outer_ids], Serialize(closure), [offset_map],
	 *   [serialized_values] ]
	 *
	 * @return the broker representation, or an error if the serialization
	 * failed.
	 */
	broker::expected<broker::data> SerializeClosureFrame(const IDPList& selection);

	/**
	 * Serializes the frame in the context of supporting copy semantics
	 * for lambdas:
	 *
	 * [ "CopyFrame", serialized_values ]
	 *
	 * where serialized_values are two-element vectors. A serialized_value
	 * has the result of calling broker::data_to_val on the value in the
	 * first index, and an integer representing that value's type in the
	 * second index.
	 */
	broker::expected<broker::data> SerializeCopyFrame();

	/**
	 * Instantiates a Frame from a serialized one.
	 *
	 * @return a pair in which the first item is the status of the serialization;
	 * and the second is the unserialized frame with reference count +1, or
	 * null if the serialization wasn't successful.
	 *
	 * The *captures* argument, if non-nil, specifies that the frame
	 * reflects captures with copy-semantics rather than deprecated
	 * reference semantics.
	 */
	static std::pair<bool, FramePtr> Unserialize(const broker::vector& data,
			const std::optional<FuncType::CaptureList>& captures);

	/**
	 * Sets the IDs that the frame knows offsets for. These offsets will
	 * be used instead of any previously provided ones for future lookups
	 * of IDs in *ids*.
	 *
	 * @param ids the ids that the frame will intake.
	 */
	void AddKnownOffsets(const IDPList& ids);

	/**
	 * Captures *c* as this frame's closure and Refs all of the values
	 * corresponding to outer_ids in that closure. This also Refs *c* as
	 * the frame will unref it upon deconstruction. When calling this,
	 * the frame's closure must not have been set yet.
	 */
	void CaptureClosure(Frame* c, IDPList outer_ids);

	// If the frame is run in the context of a trigger condition evaluation,
	// the trigger needs to be registered.
	void SetTrigger(trigger::TriggerPtr arg_trigger);
	void ClearTrigger();
	trigger::Trigger* GetTrigger() const		{ return trigger.get(); }

	void SetCall(const CallExpr* arg_call)	{ call = arg_call; }
	void ClearCall()			{ call = nullptr; }
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
	void AddFunctionWithClosureRef(ScriptFunc* func);

private:

	using OffsetMap = std::unordered_map<std::string, int>;

	struct Element {
		ValPtr val;
		// Weak reference is used to prevent circular reference memory leaks
		// in lambdas/closures.
		bool weak_ref;
	};

	const ValPtr& GetElementByID(const ID* id) const;

	/**
	 * Sets the element at index *n* of the underlying array to *v*, but does
	 * not take ownership of a reference count to it.  This method is used to
	 * break circular references between lambda functions and closure frames.
	 * @param n the index to set
	 * @param v the value to set it to (caller has not Ref'd and Frame will
	 * not Unref it)
	 */
	void SetElementWeak(int n, Val* v);

	/**
	 * Clone an element at an offset into other frame if not equal to a given
	 * function (in that case just assigna weak reference).  Used to break
	 * circular references between lambda functions and closure frames.
	 */
	void CloneNonFuncElement(int offset, ScriptFunc* func, Frame* other) const;

	/**
	 * Resets the value at offset 'n' frame (by decrementing reference
	 * count if not a weak reference).
	 */
	void ClearElement(int n);

	/** Have we captured this id?  Version for deprecated semantics. */
	bool IsOuterID(const ID* in) const;

	/** Have we captured this id?  Version for current semantics. */
	bool IsCaptureID(const ID* in) const;

	/** Serializes an offset_map */
	static broker::expected<broker::data>
	SerializeOffsetMap(const OffsetMap& in);

	/** Serializes an IDPList */
	static broker::expected<broker::data>
	SerializeIDList(const IDPList& in);

	/** Unserializes an offset map. */
	static std::pair<bool, std::unordered_map<std::string, int>>
	UnserializeOffsetMap(const broker::vector& data);

	/** Unserializes an IDPList. */
	static std::pair<bool, IDPList>
	UnserializeIDList(const broker::vector& data);

	/** The number of vals that can be stored in this frame. */
	int size;

	bool weak_closure_ref = false;
	bool break_before_next_stmt;
	bool break_on_return;
	bool delayed;

	/** Associates ID's offsets with values. */
	std::unique_ptr<Element[]> frame;

	/**
	 * The offset we're currently using for references into the frame.
	 * This is how we support inlined functions without having to
	 * alter the offsets associated with their local variables.
	 */
	int current_offset;

	/** The enclosing frame of this frame. Used for reference semantics. */
	Frame* closure;

	/** ID's used in this frame from the enclosing frame, when using
	 * reference semantics (closure != nullptr).
	 */
	IDPList outer_ids;

	/**
	 * Maps ID names to offsets. Used if this frame is  serialized
	 * to maintain proper offsets after being sent elsewhere.
	 */
	std::unique_ptr<OffsetMap> offset_map;

	/** Frame used for captures (if any) with copy semantics. */
	Frame* captures;

	/** Maps IDs to offsets into the "captures" frame.  If the ID
	 * isn't present, then it's not a capture.
	 *
	 * We keep this separate from offset_map to help ensure we don't
	 * confuse code from the deprecated semantics with the current
	 * semantics.
	 */
	const OffsetMap* captures_offset_map;

	/** The function this frame is associated with. */
	const ScriptFunc* function;

	// The following is only needed for the debugger.
	/** The arguments to the function that this Frame is associated with. */
	const zeek::Args* func_args;

	/** The next statement to be evaluted in the context of this frame. */
	Stmt* next_stmt;

	trigger::TriggerPtr trigger;
	const CallExpr* call;

	std::unique_ptr<std::vector<ScriptFunc*>> functions_with_closure_frame_reference;
};

} // namespace detail
} // namespace zeek

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
extern std::vector<zeek::detail::Frame*> g_frame_stack;
