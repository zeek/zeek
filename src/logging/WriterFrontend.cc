#include "zeek/logging/WriterFrontend.h"

#include "zeek/RunState.h"
#include "zeek/broker/Manager.h"
#include "zeek/logging/Manager.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/threading/SerialTypes.h"

using zeek::threading::Field;
using zeek::threading::Value;

namespace zeek::logging
	{

// Messages sent from frontend to backend (i.e., "InputMessages").

class InitMessage final : public threading::InputMessage<WriterBackend>
	{
public:
	InitMessage(WriterBackend* backend, const int num_fields, const Field* const* fields)
		: threading::InputMessage<WriterBackend>("Init", backend), num_fields(num_fields),
		  fields(fields)
		{
		}

	bool Process() override { return Object()->Init(num_fields, fields); }

private:
	const int num_fields;
	const Field* const* fields;
	};

class RotateMessage final : public threading::InputMessage<WriterBackend>
	{
public:
	RotateMessage(WriterBackend* backend, WriterFrontend* frontend, const char* rotated_path,
	              const double open, const double close, const bool terminating)
		: threading::InputMessage<WriterBackend>("Rotate", backend), frontend(frontend),
		  rotated_path(util::copy_string(rotated_path)), open(open), close(close),
		  terminating(terminating)
		{
		}

	virtual ~RotateMessage() { delete[] rotated_path; }

	bool Process() override { return Object()->Rotate(rotated_path, open, close, terminating); }

private:
	WriterFrontend* frontend;
	const char* rotated_path;
	const double open;
	const double close;
	const bool terminating;
	};

class WriteMessage final : public threading::InputMessage<WriterBackend>
	{
public:
	WriteMessage(WriterBackend* backend, int num_fields, int num_writes, Value*** vals)
		: threading::InputMessage<WriterBackend>("Write", backend), num_fields(num_fields),
		  num_writes(num_writes), vals(vals)
		{
		}

	bool Process() override { return Object()->Write(num_fields, num_writes, vals); }

private:
	int num_fields;
	int num_writes;
	Value*** vals;
	};

class SetBufMessage final : public threading::InputMessage<WriterBackend>
	{
public:
	SetBufMessage(WriterBackend* backend, const bool enabled)
		: threading::InputMessage<WriterBackend>("SetBuf", backend), enabled(enabled)
		{
		}

	bool Process() override { return Object()->SetBuf(enabled); }

private:
	const bool enabled;
	};

class FlushMessage final : public threading::InputMessage<WriterBackend>
	{
public:
	FlushMessage(WriterBackend* backend, double network_time)
		: threading::InputMessage<WriterBackend>("Flush", backend), network_time(network_time)
		{
		}

	bool Process() override { return Object()->Flush(network_time); }

private:
	double network_time;
	};

// Frontend methods.

WriterFrontend::WriterFrontend(const WriterBackend::WriterInfo& arg_info, EnumVal* arg_stream,
                               EnumVal* arg_writer, bool arg_local, bool arg_remote)
	{
	stream = arg_stream;
	writer = arg_writer;
	Ref(stream);
	Ref(writer);

	disabled = initialized = false;
	buf = true;
	local = arg_local;
	remote = arg_remote;
	write_buffer = nullptr;
	write_buffer_pos = 0;
	info = new WriterBackend::WriterInfo(arg_info);

	num_fields = 0;
	fields = nullptr;

	const char* w = arg_writer->GetType()->AsEnumType()->Lookup(arg_writer->InternalInt());
	name = util::copy_string(util::fmt("%s/%s", arg_info.path, w));

	if ( local )
		{
		backend = log_mgr->CreateBackend(this, writer);

		if ( backend )
			backend->Start();
		}

	else
		backend = nullptr;
	}

WriterFrontend::~WriterFrontend()
	{
	for ( auto i = 0; i < num_fields; ++i )
		delete fields[i];

	delete[] fields;

	Unref(stream);
	Unref(writer);
	delete info;
	delete[] name;
	}

void WriterFrontend::Stop()
	{
	FlushWriteBuffer();
	SetDisable();

	if ( backend )
		{
		backend->SignalStop();
		backend = nullptr; // Thread manager will clean it up once it finishes.
		}
	}

void WriterFrontend::Init(int arg_num_fields, const Field* const* arg_fields)
	{
	if ( disabled )
		return;

	if ( initialized )
		reporter->InternalError("writer initialize twice");

	num_fields = arg_num_fields;
	fields = arg_fields;

	initialized = true;

	if ( backend )
		{
		auto fs = new Field*[num_fields];

		for ( auto i = 0; i < num_fields; ++i )
			fs[i] = new Field(*fields[i]);

		backend->SendIn(new InitMessage(backend, arg_num_fields, fs));
		}

	if ( remote )
		{
		broker_mgr->PublishLogCreate(stream, writer, *info, arg_num_fields, arg_fields);
		}
	}

void WriterFrontend::Write(int arg_num_fields, Value** vals)
	{
	if ( disabled )
		{
		DeleteVals(arg_num_fields, vals);
		return;
		}

	if ( arg_num_fields != num_fields )
		{
		reporter->Warning("WriterFrontend %s expected %d fields in write, got %d. Skipping line.",
		                  name, num_fields, arg_num_fields);
		DeleteVals(arg_num_fields, vals);
		return;
		}

	if ( remote )
		{
		broker_mgr->PublishLogWrite(stream, writer, info->path, num_fields, vals);
		}

	if ( ! backend )
		{
		DeleteVals(arg_num_fields, vals);
		return;
		}

	if ( ! write_buffer )
		{
		// Need new buffer.
		write_buffer = new Value**[WRITER_BUFFER_SIZE];
		write_buffer_pos = 0;
		}

	write_buffer[write_buffer_pos++] = vals;

	if ( write_buffer_pos >= WRITER_BUFFER_SIZE || ! buf || run_state::terminating )
		// Buffer full (or no buffering desired or termiating).
		FlushWriteBuffer();
	}

void WriterFrontend::FlushWriteBuffer()
	{
	if ( ! write_buffer_pos )
		// Nothing to do.
		return;

	if ( backend )
		backend->SendIn(new WriteMessage(backend, num_fields, write_buffer_pos, write_buffer));

	// Clear buffer (no delete, we pass ownership to child thread.)
	write_buffer = nullptr;
	write_buffer_pos = 0;
	}

void WriterFrontend::SetBuf(bool enabled)
	{
	if ( disabled )
		return;

	buf = enabled;

	if ( backend )
		backend->SendIn(new SetBufMessage(backend, enabled));

	if ( ! buf )
		// Make sure no longer buffer any still queued data.
		FlushWriteBuffer();
	}

void WriterFrontend::Flush(double network_time)
	{
	if ( disabled )
		return;

	FlushWriteBuffer();

	if ( backend )
		backend->SendIn(new FlushMessage(backend, network_time));
	}

void WriterFrontend::Rotate(const char* rotated_path, double open, double close, bool terminating)
	{
	if ( disabled )
		return;

	FlushWriteBuffer();

	if ( backend )
		backend->SendIn(new RotateMessage(backend, this, rotated_path, open, close, terminating));
	else
		// Still signal log manager that we're done.
		log_mgr->FinishedRotation(this, nullptr, nullptr, 0, 0, false, terminating);
	}

void WriterFrontend::DeleteVals(int num_fields, Value** vals)
	{
	// Note this code is duplicated in Manager::DeleteVals().
	for ( int i = 0; i < num_fields; i++ )
		delete vals[i];

	delete[] vals;
	}

	} // namespace zeek::logging
