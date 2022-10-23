// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <broker/data.hh>
#include <broker/expected.hh>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "zeek/IntrusivePtr.h"
#include "zeek/Obj.h"
#include "zeek/Type.h"
#include "zeek/ZeekArgs.h"
#include "zeek/ZeekList.h" // for typedef val_list

namespace zeek
	{

using ValPtr = IntrusivePtr<Val>;

namespace detail
	{

class CallExpr;
class ScriptFunc;
using IDPtr = IntrusivePtr<ID>;

namespace trigger
	{

class Trigger;
using TriggerPtr = IntrusivePtr<Trigger>;

	}

class Frame;
using FramePtr = IntrusivePtr<Frame>;

class Frame : public Obj
	{
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
	 * @param n the index to get.
	 * @return the value at index *n* of the underlying array.
	 */
	const ValPtr& GetElement(int n) const
		{
		// Note: technically this may want to adjust by current_offset, but
		// in practice, this method is never called from anywhere other than
		// function call invocation, where current_offset should be zero.
		return frame[n];
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
	void SetElement(const IDPtr& id, ValPtr v) { SetElement(id.get(), std::move(v)); }

	/**
	 * Gets the value associated with *id* and returns it. Returns
	 * nullptr if no such element exists.
	 *
	 * @param id the id who's value to retreive
	 * @return the value associated with *id*
	 */
	const ValPtr& GetElementByID(const IDPtr& id) const { return GetElementByID(id.get()); }

	/**
	 * Adjusts the current offset being used for frame accesses.
	 * This is in support of inlined functions.
	 *
	 * @param incr  Amount by which to increase the frame offset.
	 *              Use a negative value to shrink the offset.
	 */
	void AdjustOffset(int incr) { current_offset += incr; }

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
	const ScriptFunc* GetFunction() const { return function; }

	/**
	 * @return the arguments passed to the function that this frame
	 * is associated with.
	 */
	const Args* GetFuncArgs() const { return func_args; }

	/**
	 * Change the function that the frame is associated with.
	 *
	 * @param func the function for the frame to be associated with.
	 */
	void SetFunction(ScriptFunc* func) { function = func; }

	/**
	 * Sets the next statement to be executed in the context of the frame.
	 *
	 * @param stmt the statement to set it to.
	 */
	void SetNextStmt(Stmt* stmt) { next_stmt = stmt; }

	/**
	 * @return the next statement to be executed in the context of the frame.
	 */
	Stmt* GetNextStmt() const { return next_stmt; }

	/** Used to implement "next" command in debugger. */
	void BreakBeforeNextStmt(bool should_break) { break_before_next_stmt = should_break; }
	bool BreakBeforeNextStmt() const { return break_before_next_stmt; }

	/** Used to implement "finish" command in debugger. */
	void BreakOnReturn(bool should_break) { break_on_return = should_break; }
	bool BreakOnReturn() const { return break_on_return; }

	/**
	 * Performs a deep copy of all the values in the current frame.
	 *
	 * @return a copy of this frame.
	 */
	Frame* Clone() const;

	/**
	 * Serializes the frame in support of copy semantics for lambdas:
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
	static std::pair<bool, FramePtr>
	Unserialize(const broker::vector& data, const std::optional<FuncType::CaptureList>& captures);

	// If the frame is run in the context of a trigger condition evaluation,
	// the trigger needs to be registered.
	void SetTrigger(trigger::TriggerPtr arg_trigger);
	void ClearTrigger();
	trigger::Trigger* GetTrigger() const { return trigger.get(); }

	void SetCall(const CallExpr* arg_call)
		{
		call = arg_call;
		SetTriggerAssoc((void*)call);
		}
	const CallExpr* GetCall() const { return call; }

	void SetTriggerAssoc(const void* arg_assoc) { assoc = arg_assoc; }
	const void* GetTriggerAssoc() const { return assoc; }

	void SetCallLoc(const Location* loc) { call_loc = loc; }
	const detail::Location* GetCallLocation() const;

	void SetDelayed() { delayed = true; }
	bool HasDelayed() const { return delayed; }

private:
	using OffsetMap = std::unordered_map<std::string, int>;

	// This has a trivial form now, but used to hold additional
	// information, which is why we abstract it away from just being
	// a ValPtr.
	using Element = ValPtr;

	const ValPtr& GetElementByID(const ID* id) const;

	/** The number of vals that can be stored in this frame. */
	int size;

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

	/** Frame used for captures (if any) with copy semantics. */
	Frame* captures;

	/** Maps IDs to offsets into the "captures" frame.  If the ID
	 * isn't present, then it's not a capture.
	 */
	const OffsetMap* captures_offset_map;

	/** The function this frame is associated with. */
	const ScriptFunc* function;

	// The following is only needed for the debugger.
	/** The arguments to the function that this Frame is associated with. */
	const zeek::Args* func_args;

	/** The next statement to be evaluated in the context of this frame. */
	Stmt* next_stmt;

	trigger::TriggerPtr trigger;
	const CallExpr* call = nullptr;
	const void* assoc = nullptr;
	const Location* call_loc = nullptr; // only needed if call is nil
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
