#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "PersistenceSerializer.h"
#include "RemoteSerializer.h"
#include "Conn.h"
#include "Event.h"
#include "Reporter.h"
#include "Net.h"

class IncrementalWriteTimer : public Timer {
public:
	IncrementalWriteTimer(double t, PersistenceSerializer::SerialStatus* s)
		: Timer(t, TIMER_INCREMENTAL_WRITE), status(s)	{}

	void Dispatch(double t, int is_expire);

	PersistenceSerializer::SerialStatus* status;
};

void IncrementalWriteTimer::Dispatch(double t, int is_expire)
	{
	// Never suspend when we're finishing up.
	if ( terminating )
		status->info.may_suspend = false;

	persistence_serializer->RunSerialization(status);
	}

PersistenceSerializer::PersistenceSerializer()
	{
	dir = 0;
	}

PersistenceSerializer::~PersistenceSerializer()
	{
	}

void PersistenceSerializer::Register(ID* id)
	{
	if ( id->Type()->Tag() == TYPE_FUNC )
		{
		Error("can't register functions as persistent ID");
		return;
		}

	DBG_LOG(DBG_STATE, "&persistent %s", id->Name());

	HashKey key(id->Name());
	if ( persistent_ids.Lookup(&key) )
		return;

	Ref(id);
	persistent_ids.Insert(&key, id);
	}

void PersistenceSerializer::Unregister(ID* id)
	{
	HashKey key(id->Name());
	Unref((ID*) persistent_ids.Remove(&key));
	}

void PersistenceSerializer::Register(Connection* conn)
	{
	if ( persistent_conns.Lookup(conn->Key()) )
		return;

	Ref(conn);
	HashKey* k = conn->Key();
	HashKey* new_key = new HashKey(k->Key(), k->Size(), k->Hash());
	persistent_conns.Insert(new_key, conn);
	delete new_key;
	}

void PersistenceSerializer::Unregister(Connection* conn)
	{
	Unref(persistent_conns.RemoveEntry(conn->Key()));
	}

bool PersistenceSerializer::CheckTimestamp(const char* file)
	{
	struct stat s;
	if ( stat(file, &s) < 0 )
		return false;

	if ( ! S_ISREG(s.st_mode) )
		return false;

	bool changed = true;

	HashKey* key = new HashKey(file, strlen(file));
	time_t* t = files.Lookup(key);

	if ( ! t )
		{
		t = (time_t*) malloc(sizeof(time_t));
		if ( ! t )
			out_of_memory("saving file timestamp");
		files.Insert(key, t);
		}

	else if ( *t >= s.st_mtime )
		changed = false;

	*t = s.st_mtime;

	delete key;
	return changed;
	}

bool PersistenceSerializer::CheckForFile(UnserialInfo* info, const char* file,
						bool delete_file)
	{
	bool ret = true;
	if ( CheckTimestamp(file) )
		{
		// Need to copy the filename here, as it may be passed
		// in via fmt().
		const char* f = copy_string(file);

		bool ret = Read(info, f);

		if ( delete_file && unlink(f) < 0 )
			Error(fmt("can't delete file %s: %s", f, strerror(errno)));

		delete [] f;
		}

	return ret;
	}

bool PersistenceSerializer::ReadAll(bool is_init, bool delete_files)
	{
#ifdef USE_PERFTOOLS_DEBUG
	HeapLeakChecker::Disabler disabler;
#endif

	assert(dir);

	UnserialInfo config_info(this);
	config_info.id_policy = is_init ?
			UnserialInfo::Replace : UnserialInfo::CopyCurrentToNew;

	if ( ! CheckForFile(&config_info, fmt("%s/config.bst", dir),
				delete_files) )
		return false;

	UnserialInfo state_info(this);
	state_info.id_policy = UnserialInfo::CopyNewToCurrent;
	if ( ! CheckForFile(&state_info, fmt("%s/state.bst", dir),
				delete_files) )
		return false;

	return true;
	}

bool PersistenceSerializer::MoveFileUp(const char* dir, const char* file)
	{
	char oldname[PATH_MAX];
	char newname[PATH_MAX];

	safe_snprintf(oldname, PATH_MAX, "%s/.tmp/%s", dir, file );
	safe_snprintf(newname, PATH_MAX, "%s/%s", dir, file );

	if ( rename(oldname, newname) < 0 )
		{
		Error(fmt("can't move %s to %s: %s", oldname, newname,
				strerror(errno)));
		return false;
		}

	CheckTimestamp(newname);
	return true;
	}

#if 0
void PersistenceSerializer::RaiseFinishedSendState()
	{
	val_list* vl = new val_list;
	vl->append(new AddrVal(htonl(remote_host)));
	vl->append(new PortVal(remote_port));

	mgr.QueueEvent(finished_send_state, vl);
	reporter->Log("Serialization done.");
	}
#endif

void PersistenceSerializer::GotEvent(const char* name, double time,
					EventHandlerPtr event, val_list* args)
	{
	mgr.QueueEvent(event, args);
	}

void PersistenceSerializer::GotFunctionCall(const char* name, double time,
					Func* func, val_list* args)
	{
	try
		{
		func->Call(args);
		}

	catch ( InterpreterException& e )
		{ /* Already reported. */ }
	}

void PersistenceSerializer::GotStateAccess(StateAccess* s)
	{
	s->Replay();
	delete s;
	}

void PersistenceSerializer::GotTimer(Timer* s)
	{
	reporter->Error("PersistenceSerializer::GotTimer not implemented");
	}

void PersistenceSerializer::GotConnection(Connection* c)
	{
	Unref(c);
	}

void PersistenceSerializer::GotID(ID* id, Val* /* val */)
	{
	Unref(id);
	}

void PersistenceSerializer::GotPacket(Packet* p)
	{
	reporter->Error("PersistenceSerializer::GotPacket not implemented");
	}

bool PersistenceSerializer::LogAccess(const StateAccess& s)
	{
	if ( ! IsSerializationRunning() )
		return true;

	loop_over_list(running, i)
		{
		running[i]->accesses.append(new StateAccess(s));
		}

	return true;
	}

bool PersistenceSerializer::WriteState(bool may_suspend)
	{
	SerialStatus* status =
		new SerialStatus(this, SerialStatus::WritingState);

	status->info.may_suspend = may_suspend;

	status->ids = &persistent_ids;
	status->conns = &persistent_conns;
	status->filename = "state.bst";

	return RunSerialization(status);
	}

bool PersistenceSerializer::WriteConfig(bool may_suspend)
	{
	if ( mgr.IsDraining() && may_suspend )
		// Events which trigger checkpoint are flushed. Ignore; we'll
		// checkpoint at termination in any case.
		return true;

	SerialStatus* status =
		new SerialStatus(this, SerialStatus::WritingConfig);

	status->info.may_suspend = may_suspend;
	status->info.clear_containers = true;
	status->ids = global_scope()->GetIDs();
	status->filename = "config.bst";

	return RunSerialization(status);
	}

bool PersistenceSerializer::SendState(SourceID peer, bool may_suspend)
	{
	SerialStatus* status =
		new SerialStatus(remote_serializer, SerialStatus::SendingState);

	status->info.may_suspend = may_suspend;
	status->ids = &persistent_ids;
	status->conns = &persistent_conns;
	status->peer = peer;

	reporter->Info("Sending state...");

	return RunSerialization(status);
	}

bool PersistenceSerializer::SendConfig(SourceID peer, bool may_suspend)
	{
	SerialStatus* status =
		new SerialStatus(remote_serializer, SerialStatus::SendingConfig);

	status->info.may_suspend = may_suspend;
	status->info.clear_containers = true;
	status->ids = global_scope()->GetIDs();
	status->peer = peer;

	reporter->Info("Sending config...");

	return RunSerialization(status);
	}

bool PersistenceSerializer::RunSerialization(SerialStatus* status)
	{
	Continuation* cont = &status->info.cont;

	if ( cont->NewInstance() )
		{
		// Serialization is starting. Initialize.

		// See if there is already a serialization of this type running.
		loop_over_list(running, i)
			{
			if ( running[i]->type == status->type )
				{
				reporter->Warning("Serialization of type %d already running.", status->type);
				return false;
				}
			}

		running.append(status);

		// Initialize.
		if ( ! (ensure_dir(dir) && ensure_dir(fmt("%s/.tmp", dir))) )
			return false;

		if ( ! OpenFile(fmt("%s/.tmp/%s", dir, status->filename), false) )
			return false;

		if ( ! PrepareForWriting() )
			return false;

		if ( status->ids )
			{
			status->id_cookie = status->ids->InitForIteration();
			status->ids->MakeRobustCookie(status->id_cookie);
			}

		if ( status->conns )
			{
			status->conn_cookie = status->conns->InitForIteration();
			status->conns->MakeRobustCookie(status->conn_cookie);
			}
		}

	else if ( cont->ChildSuspended() )
		{
		// One of our former Serialize() calls suspended itself.
		// We have to call it again.

		if ( status->id_cookie )
			{
			if ( ! DoIDSerialization(status, status->current.id) )
				return false;

			if ( cont->ChildSuspended() )
				{
				// Oops, it did it again.
				timer_mgr->Add(new IncrementalWriteTimer(network_time + state_write_delay, status));
				return true;
				}
			}

		else if ( status->conn_cookie )
			{
			if ( ! DoConnSerialization(status, status->current.conn) )
				return false;

			if ( cont->ChildSuspended() )
				{
				// Oops, it did it again.
				timer_mgr->Add(new IncrementalWriteTimer(network_time + state_write_delay, status));
				return true;
				}
			}

		else
			reporter->InternalError("unknown suspend state");
		}

	else if ( cont->Resuming() )
		cont->Resume();

	else
		reporter->InternalError("unknown continuation state");

	if ( status->id_cookie )
		{
		ID* id;

		while ( (id = status->ids->NextEntry(status->id_cookie)) )
			{
			if ( ! DoIDSerialization(status, id) )
				return false;

			if ( cont->ChildSuspended() )
				{
				timer_mgr->Add(new IncrementalWriteTimer(network_time + state_write_delay, status));
				return true;
				}

			if ( status->info.may_suspend )
				{
				timer_mgr->Add(new IncrementalWriteTimer(network_time + state_write_delay, status));
				cont->Suspend();
				return true;
				}
			}

		// Cookie has been set to 0 by NextEntry().
		}

	if ( status->conn_cookie )
		{
		Connection* conn;
		while ( (conn = status->conns->NextEntry(status->conn_cookie)) )
			{
			if ( ! DoConnSerialization(status, conn) )
				return false;

			if ( cont->ChildSuspended() )
				{
				timer_mgr->Add(new IncrementalWriteTimer(network_time + state_write_delay, status));
				return true;
				}

			if ( status->info.may_suspend )
				{
				timer_mgr->Add(new IncrementalWriteTimer(network_time + state_write_delay, status));
				cont->Suspend();
				return true;
				}

			}

		// Cookie has been set to 0 by NextEntry().
		}

	DBG_LOG(DBG_STATE, "finished serialization; %d accesses pending",
			status->accesses.length());

	if ( status->accesses.length() )
		{
		// Serialize pending state accesses.
		// FIXME: Does this need to suspend?
		StateAccess* access;
		loop_over_list(status->accesses, i)
			{
			// Serializing a StateAccess will not suspend.
			if ( ! DoAccessSerialization(status, status->accesses[i]) )
				return false;

			delete status->accesses[i];
			}
		}

	// Finalize.
	CloseFile();

	bool ret = MoveFileUp(dir, status->filename);

	loop_over_list(running, i)
		{
		if ( running[i]->type == status->type )
			{
			running.remove_nth(i);
			break;
			}
		}

	delete status;
	return ret;
	}

bool PersistenceSerializer::DoIDSerialization(SerialStatus* status, ID* id)
	{
	bool success = false;
	Continuation* cont = &status->info.cont;

	status->current.id = id;

	switch ( status->type ) {
	case SerialStatus::WritingState:
	case SerialStatus::WritingConfig:
		cont->SaveContext();
		success = Serialize(&status->info, *id);
		cont->RestoreContext();
		break;

	case SerialStatus::SendingState:
	case SerialStatus::SendingConfig:
		cont->SaveContext();
		success = remote_serializer->SendID(&status->info,
							status->peer, *id);
		cont->RestoreContext();
		break;

	default:
		reporter->InternalError("unknown serialization type");
	}

	return success;
	}

bool PersistenceSerializer::DoConnSerialization(SerialStatus* status,
						Connection* conn)
	{
	bool success = false;
	Continuation* cont = &status->info.cont;

	status->current.conn = conn;

	switch ( status->type ) {
	case SerialStatus::WritingState:
	case SerialStatus::WritingConfig:
		cont->SaveContext();
		success = Serialize(&status->info, *conn);
		cont->RestoreContext();
		break;

	case SerialStatus::SendingState:
	case SerialStatus::SendingConfig:
		cont->SaveContext();
		success = remote_serializer->SendConnection(&status->info,
							status->peer, *conn);
		cont->RestoreContext();
		break;

	default:
		reporter->InternalError("unknown serialization type");
	}

	return success;
	}

bool PersistenceSerializer::DoAccessSerialization(SerialStatus* status,
							StateAccess* access)
	{
	bool success = false;
	DisableSuspend suspend(&status->info);

	switch ( status->type ) {
	case SerialStatus::WritingState:
	case SerialStatus::WritingConfig:
		success = Serialize(&status->info, *access);
		break;

	case SerialStatus::SendingState:
	case SerialStatus::SendingConfig:
		success = remote_serializer->SendAccess(&status->info,
							status->peer, *access);
		break;

	default:
		reporter->InternalError("unknown serialization type");
	}

	return success;
	}
