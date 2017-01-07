// See the file "COPYING" in the main distribution directory for copyright.
//
// This follows roughly the idea from
// http://www.1024cores.net/home/lock-free-algorithms/tricks/fibers for
// speeding up context switches. It borrows some of the implementation from
// HILTI, https://www.icir.org/hilti.

#include "Fiber.h"
#include "Reporter.h"

static const unsigned int STACK_SIZE = 327680;
static const unsigned int CACHE_SIZE = 100;

std::vector<std::shared_ptr<Fiber>> Fiber::cache;
uint64 Fiber::total_fibers = 0;
uint64 Fiber::current_fibers = 0;
uint64 Fiber::max_fibers = 0;

extern "C" {
void _Trampoline(unsigned int y, unsigned int x)
	{
	// Magic from from libtask/task.c to turn the two words back into a pointer.
	unsigned long z;
	z = (x << 16);
	z <<= 16;
	z |= y;
	Fiber* fiber = (Fiber*)z;

	// Via recycling a fiber can run an arbitrary number of user jobs. So
	// this trampoline is really a loop that yields after it has finished its
	// run() function, and expects a new run function once it's resumed.

	while ( 1 )
		{
		assert(fiber->state == Fiber::RUNNING);

		if ( ! _setjmp(fiber->trampoline) )
			{
			fiber->success = fiber->run();
			fiber->state = Fiber::FINISHED;
			}

		if ( ! _setjmp(fiber->fiber) )
			{
			fiber->run = 0;
			fiber->state = Fiber::IDLE;
			_longjmp(fiber->parent, 1);
			}
		}

	// Cannot be reached.
	abort();
	}
}

Fiber::Fiber()
	{
	DBG_LOG(DBG_NOTIFIERS, "allocated new fiber %p", this);

	if ( getcontext(&uctx) < 0 )
		reporter->InternalError("getcontext failed");

	state = INIT;
	resumed = false;
	success = false;
	uctx.uc_link = 0;
	uctx.uc_stack.ss_size = STACK_SIZE;
	uctx.uc_stack.ss_sp = safe_malloc(STACK_SIZE);
	uctx.uc_stack.ss_flags = 0;
	obj = nullptr;

	// Magic from from libtask/task.c to turn the pointer into two words.
	// TODO: Probably not portable ...
	unsigned long z = (unsigned long)this;
	unsigned int y = z;
	z >>= 16;
	unsigned int x = (z >> 16);

	makecontext(&uctx, (void (*)())_Trampoline, 2, y, x);

	++total_fibers;
	++current_fibers;

	if ( current_fibers > max_fibers )
		max_fibers = current_fibers;
	}

Fiber::~Fiber()
	{
	free(uctx.uc_stack.ss_sp);
	Unref(obj);
	--current_fibers;
	}

bool Fiber::Run()
	{
	int init = (state == INIT);

	state = RUNNING;

	if ( ! _setjmp(parent) )
		{
		if ( init )
			setcontext(&uctx);
		else
			_longjmp(fiber, 1);

		abort();
		}

	switch ( state ) {
	case YIELDED:
        	return 0;

	case IDLE:
        	return 1;

	default:
        	abort();
	}
	}

bool Fiber::Execute(std::function<bool ()> f)
	{
	assert(state == Fiber::INIT || state == Fiber::IDLE);
	run = f;
	resumed = false;
	success = false;
	return Run();
	}

void Fiber::Yield()
	{
	assert(state == Fiber::RUNNING);

	if ( ! _setjmp(fiber) )
		{
		state = YIELDED;
		_longjmp(parent, 1);
		}
	}

bool Fiber::Resume()
	{
	resumed = true;
	return Run();
	}

bool Fiber::HasResumed()
	{
	return resumed;
	}

bool Fiber::Success()
	{
	return success;
	}

void Fiber::UnrefObj(BroObj *arg_obj)
	{
	Unref(obj);
	obj = arg_obj;
	}

std::shared_ptr<Fiber> Fiber::Create()
	{
	if ( cache.size() )
		{
	    	std::shared_ptr<Fiber> f = cache.back();
		cache.pop_back();
	        return f;
		}
	else
		return std::make_shared<Fiber>();
	}

void Fiber::Destroy(std::shared_ptr<Fiber> fiber)
	{
	Unref(fiber->obj);
	fiber->obj = 0;

	if ( cache.size() < CACHE_SIZE  )
		{
		DBG_LOG(DBG_NOTIFIERS, "putting fiber %p back into cache", fiber.get());
		cache.push_back(fiber);
		}
	else
		{
		DBG_LOG(DBG_NOTIFIERS, "fiber %p ready for deletion", fiber.get());
		}
	}

void Fiber::Done()
	{
	DBG_LOG(DBG_NOTIFIERS, "termination: clearing cache");
	cache.clear();
	}

const Fiber::Stats& Fiber::GetStats()
	{
	static Stats stats;
	stats.max = max_fibers;
	stats.total = total_fibers;
	stats.current = current_fibers;
	stats.cached = cache.size();
	return stats;
 	}
