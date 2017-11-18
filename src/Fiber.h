// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FIBER_H
#define FIBER_H

#include <setjmp.h>
#include <functional>
#include <vector>
#include <memory>

#include "Obj.h"

class Trigger;

extern "C" {
    #include "3rdparty/libtask/taskimpl.h"
    void _Trampoline(unsigned int y, unsigned int x);
}

/**
  * Class faciliating transfering control between co-routines.
  */
class Fiber
{
public:
	/**
	 * Constructor. Don't create object directly, use Create() instead.
	 */
	Fiber();

	/**
	 * Destructor. Don't destroy object directly, use Destroy() instead.
	 */
	~Fiber();

	/**
	 * Starts executing a function inside the fiber. The function can
	 * call Yield() to yield control back to the caller.
	 *
	 * @param f The function to execute. The function can signal success
	 * by returning a boolean value at termination.
	 *
	 * @return True if the function ran to completion, and false if the
	 * function yielded. In the latter case, calling Resume() will
	 * continue the function's execution.
	 */
	bool Execute(std::function<bool ()> f);

	/**
	 * When called from inside the executed function, it returns control
	 * back to the caller.
	 */
	void Yield();

	/**
	 * When called after the executed function yielded, it resumes its
	 * execution where it left off.
	 */
	bool Resume();

	/**
	 * Returns true if the function has been resumed at least once.
	 */
	bool HasResumed();

	/**
	 * Returns the function boolean return value once it has run to
	 * completetion.
	 */
	bool Success();

	void UnrefObj(BroObj *obj);

	void SetTrigger(Trigger *t)	{ trigger = t; }
	Trigger* GetTrigger()	{ return trigger; }

	/**
	 * Returns a new Fiber to use. Use this instead of the ``new``
	 * operator. The fiber may have either been just created, or recycled
	 * from the cache.
	 */
	static std::shared_ptr<Fiber> Create();

	/**
	 * Frees up a fiber, either returning it to the cache or deleting it.
	 */
	static void Destroy(std::shared_ptr<Fiber> fiber);

	/**
	 * Cleans up instance cache.
	 */
	static void Done();

	struct Stats {
		/**
		 *  Total number of fibers allocated so far (not counting recycled ones().
		 */
		uint64_t total;

		/**
		 *  Number of fibers currently instantiated.
		 */
		uint64_t current;

		/**
		 *  Number of fibers currently cached.
		 */
		uint64_t cached;

		/**
		 *  Maximum number of fibers concurrently allocated so far.
		 */
		uint64_t max;
	};

	/**
	 * Returns statistics about Bro's use of fibers.
	 */
	static const Stats& GetStats();

private:
	friend void _Trampoline(unsigned int y, unsigned int x);

	bool Run();

	enum State { INIT, RUNNING, YIELDED, IDLE, FINISHED };

	State state;
	ucontext_t uctx;
	jmp_buf fiber;
	jmp_buf trampoline;
	jmp_buf parent;
	std::function<bool ()> run;
	bool success;
	bool resumed;
	BroObj* obj;
	Trigger* trigger;

	// Cache of previously allocated, but currently unused Fiber
	// instances.
	static std::vector<std::shared_ptr<Fiber>> cache;

	static uint64 total_fibers;
	static uint64 current_fibers;
	static uint64 max_fibers;
};

#endif
