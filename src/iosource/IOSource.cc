#include "IOSource.h"
#include "DebugLogger.h"
#include "Manager.h"

using namespace iosource;

static void prepare_callback(uv_prepare_t* handle)
	{
	uv_handle_t* h = reinterpret_cast<uv_handle_t*>(handle);
	if ( auto src = reinterpret_cast<IOSource::Source*>(uv_handle_get_data(h)) )
		src->source->HandleNewData(src->fd);
	}

static void idle_callback(uv_idle_t* handle)
	{
	uv_handle_t* h = reinterpret_cast<uv_handle_t*>(handle);
	if ( auto src = reinterpret_cast<IOSource::Source*>(uv_handle_get_data(h)) )
		src->source->HandleNewData(src->fd);
	}

static void poll_callback(uv_poll_t* handle, int status, int error)
	{
	// Don't grab new data if there was an error with the poll.
	if ( error != 0 )
		{
		uv_handle_t* h = reinterpret_cast<uv_handle_t*>(handle);
		if ( auto src = reinterpret_cast<IOSource::Source*>(uv_handle_get_data(h)) )
			src->source->HandleNewData(src->fd);
		}
	}

static void close_callback(uv_handle_t* handle)
	{
	if ( auto src = reinterpret_cast<IOSource::Source*>(uv_handle_get_data(handle)) )
		src->source->Cleanup(src->fd);
	}

IOSource::IOSource(bool use_idle_handle) : use_idle_handle(use_idle_handle)
	{
	}

IOSource::~IOSource()
	{
	Done();
	}

bool IOSource::Start(int fd)
	{
	uv_loop_t* loop = iosource_mgr->GetLoop();
	
	if ( fd == -1 )
		{
		// We can only have one prepare or idle handle per IOSource because we have no way to
		// differentiate them from each other when processing data. Just throw an error and
		// return.
		if ( use_idle_handle )
			{
			if ( idle_handle )
				{
				DBG_LOG(DBG_PKTIO, "IOSource can't open more than one prepare handle at a time");
				return false;
				}

			idle_handle = new uv_idle_t();

			int r = uv_idle_init(loop, idle_handle);
			if ( r != 0 )
				{
				DBG_LOG(DBG_PKTIO, "IOSource failed to open init handle: %s", uv_strerror(r));
				Done();
				return false;
				}

			r = uv_idle_start(idle_handle, idle_callback);
			if ( r != 0 )
				{
				DBG_LOG(DBG_PKTIO, "IOSource failed to start init handle: %s", uv_strerror(r));
				Done();
				return false;
				}

			Source* src = new Source{ this, fd };
			uv_handle_set_data(reinterpret_cast<uv_handle_t*>(idle_handle), src);
			}
		else
			{
			if ( prepare_handle )
				{
				DBG_LOG(DBG_PKTIO, "IOSource can't open more than one idle handle at a time");
				return false;
				}
		
			prepare_handle = new uv_prepare_t();

			int r = uv_prepare_init(loop, prepare_handle);
			if ( r != 0 )
				{
				DBG_LOG(DBG_PKTIO, "IOSource failed to open init handle: %s", uv_strerror(r));
				Done();
				return false;
				}

			r = uv_prepare_start(prepare_handle, prepare_callback);
			if ( r != 0 )
				{
				DBG_LOG(DBG_PKTIO, "IOSource failed to start init handle: %s", uv_strerror(r));
				Done();
				return false;
				}

			Source* src = new Source{ this, fd };
			uv_handle_set_data(reinterpret_cast<uv_handle_t*>(prepare_handle), src);
			}
		}
	else
		{
		// Check to see if this file descriptor is already in the map. Ignore if so.
		auto it = poll_handles.find(fd);
		if ( it != poll_handles.end() )
			return false;
		
		uv_poll_t* poll = new uv_poll_t();

		int r = uv_poll_init(loop, poll, fd);
		if ( r != 0 )
			{
			DBG_LOG(DBG_PKTIO, "IOSource failed to start poll handle: %s", uv_strerror(r));
			Done();
			return false;
			}

		r = uv_poll_start(poll, UV_READABLE | UV_DISCONNECT, poll_callback);
		if ( r != 0 )
			{
			DBG_LOG(DBG_PKTIO, "IOSource failed to start poll handle: %s", uv_strerror(r));
			Done();
			return false;
			}

		Source* src = new Source{ this, fd };
		uv_handle_set_data(reinterpret_cast<uv_handle_t*>(poll), src);
		poll_handles[fd] = poll;
		}

	// Wake up the poll loop so that this new source gets added to the loop instead
	// of waiting for the next pass through the loop.
	iosource_mgr->WakeupLoop();

	return true;
	}

void IOSource::Stop(int fd)
	{
	if ( fd == -1 )
		{
		if ( prepare_handle && uv_is_closing((uv_handle_t*)prepare_handle) == 0 )
			{
			uv_prepare_stop(prepare_handle);
			uv_close(reinterpret_cast<uv_handle_t*>(prepare_handle), close_callback);
			}
	
		if ( idle_handle && uv_is_closing((uv_handle_t*)idle_handle) == 0 )
			{
			uv_idle_stop(idle_handle);
			uv_close(reinterpret_cast<uv_handle_t*>(idle_handle), close_callback);
			}
		}
	else
		{		
		auto it = poll_handles.find(fd);
		if ( it != poll_handles.end() )
			{
			if ( uv_is_closing((uv_handle_t*)it->second) == 0 )
				{
				uv_poll_stop(it->second);
				uv_close(reinterpret_cast<uv_handle_t*>(it->second), close_callback);
				}
			}
		}

	// Wake up the poll loop so that this source gets removed from the loop instead
	// of waiting for the next pass through the loop.
	iosource_mgr->WakeupLoop();
	}

void IOSource::Cleanup(int fd)
	{
	if ( fd == -1 )
		{
		if ( prepare_handle )
			{
			delete prepare_handle;
			prepare_handle = nullptr;
			}

		if ( idle_handle )
			{
			delete idle_handle;
			idle_handle = nullptr;
			}
		}
	else
		{
		auto it = poll_handles.find(fd);
		if ( it != poll_handles.end() )
			{
			delete it->second;
			poll_handles.erase(it);
			}
		}
	}

void IOSource::Done()
	{
	if ( idle_handle && uv_is_closing((uv_handle_t*)idle_handle) == 0 )
		{
		uv_idle_stop(idle_handle);
		uv_close(reinterpret_cast<uv_handle_t *>(idle_handle), close_callback);
		}

	if ( prepare_handle && uv_is_closing((uv_handle_t*)prepare_handle) == 0 )
		{
		uv_prepare_stop(prepare_handle);
		uv_close(reinterpret_cast<uv_handle_t *>(prepare_handle), close_callback);
		}

	for ( auto poll_h : poll_handles )
		{
		if ( uv_is_closing((uv_handle_t*)poll_h.second) == 0 )
			{
			uv_poll_stop(poll_h.second);
			uv_close(reinterpret_cast<uv_handle_t *>(poll_h.second), close_callback);
			}
		}

	if ( IsPacketSource () )
		iosource_mgr->Unregister(this);
	}
