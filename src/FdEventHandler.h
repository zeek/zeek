#ifndef FD_EVENT_HANDLER_H
#define FD_EVENT_HANDLER_H

#include "caf/io/broker.hpp"
#include "caf/io/network/default_multiplexer.hpp"

namespace iosource {
    class IOSource;
}

class FdEventHandler : public caf::io::network::event_handler {
public:
	FdEventHandler(iosource::IOSource* source, caf::io::broker* runloop, int fd);

	~FdEventHandler() {}

	bool EnableReadEvents();

	bool DisableReadEvents();

	bool EnableWriteEvents();

	bool DisableWriteEvents();

	bool EnableErrorEvents();

	bool DisableErrorEvents();

	void Shutdown();

private:
	void handle_event(caf::io::network::operation op) override;

	void removed_from_loop(caf::io::network::operation op) override;

	bool shutting_down;
	bool read_enabled;
	bool write_enabled;
	bool error_enabled;
	// Pointer to runloop broker actor.
	caf::io::broker* runloop;
	// Pointer that "owns" the parent actor, keeping it alive.
	caf::strong_actor_ptr strong_ptr;
	iosource::IOSource* source;
};

struct IOEvent {
	FdEventHandler* handler;
	iosource::IOSource* source;
	caf::io::network::operation op;
	int fd;
};

CAF_ALLOW_UNSAFE_MESSAGE_TYPE(IOEvent)

#endif
