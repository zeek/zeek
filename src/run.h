#ifndef run_h
#define run_h

#include "Flare.h"
#include "FdEventHandler.h"

#include <caf/io/broker.hpp>
#include <caf/io/network/default_multiplexer.hpp>

extern bro::Flare* signal_flare;

void run();

struct run_state {
	// Collection of active sources.
	std::vector<IOEvent> events;
	FdEventHandler* signal_handler;

	~run_state();
};

using runloop_actor = caf::stateful_actor<run_state, caf::io::broker>;

inline caf::io::network::default_multiplexer&
runloop_backend(caf::io::broker* r)
	{
	return dynamic_cast<caf::io::network::default_multiplexer&>(r->backend());
	}

#endif
