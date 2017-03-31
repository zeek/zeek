#include "FdEventHandler.h"
#include "iosource/IOSource.h"

FdEventHandler::FdEventHandler(iosource::IOSource* source,
                               caf::io::broker* runloop,
                               int fd)
    : caf::io::network::event_handler(runloop_backend(runloop), fd),
      read_enabled(false), write_enabled(false), error_enabled(false),
      runloop(runloop),
      strong_ptr(caf::actor_cast<caf::strong_actor_ptr>(runloop)),
      source(source)
	{
	}

bool FdEventHandler::EnableReadEvents()
	{
	if ( read_enabled )
		return false;

	backend().add(caf::io::network::operation::read, fd(), this);
	read_enabled = true;
	return true;
	}

bool FdEventHandler::DisableReadEvents()
	{
	if ( ! read_enabled )
		return false;

	backend().del(caf::io::network::operation::read, fd(), this);
	return true;
	}

bool FdEventHandler::EnableWriteEvents()
	{
	if ( write_enabled )
		return false;

	backend().add(caf::io::network::operation::write, fd(), this);
	write_enabled = true;
	return true;
	}

bool FdEventHandler::DisableWriteEvents()
	{
	if ( ! write_enabled )
		return false;

	backend().del(caf::io::network::operation::write, fd(), this);
	return true;
	}

bool FdEventHandler::EnableErrorEvents()
	{
	if ( error_enabled )
		return false;

	backend().add(caf::io::network::operation::propagate_error, fd(), this);
	error_enabled = true;
	return true;
	}

bool FdEventHandler::DisableErrorEvents()
	{
	if ( ! error_enabled )
		return false;

	backend().del(caf::io::network::operation::propagate_error, fd(), this);
	return true;
	}

void FdEventHandler::handle_event(caf::io::network::operation op)
	{
	if ( ! runloop )
		// The broker previously signaled a shutdown.
		return;

	caf::mailbox_element_vals<IOEvent> val{nullptr,
		        caf::message_id::make(), {}, IOEvent{this, source, op, fd()}};
	runloop->activate(&backend(), val);
	}

void FdEventHandler::removed_from_loop(caf::io::network::operation op)
	{
	if ( op == caf::io::network::operation::read )
		read_enabled = false;
	else if ( op == caf::io::network::operation::write )
		write_enabled = false;
	else if ( op == caf::io::network::operation::propagate_error )
		error_enabled = false;

	if ( ! read_enabled && ! write_enabled && ! error_enabled )
		delete this;
	}

void FdEventHandler::Shutdown()
	{
	// Unregister event handler from multiplexer, causing event handler
	// to delete itself.  Strong pointer will be reset by the dtor
	// once multiplexer removes the handler from the I/O loop.
	shutting_down = true;
	DisableReadEvents();
	DisableWriteEvents();
	DisableErrorEvents();
	runloop = nullptr;

	if ( ! read_enabled && ! write_enabled && ! error_enabled )
		delete this;
	}
