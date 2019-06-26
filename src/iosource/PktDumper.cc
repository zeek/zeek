
// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <sys/stat.h>

#include "zeek-config.h"

#include "PktDumper.h"

using namespace iosource;

PktDumper::PktDumper()
	{
	is_open = false;
	errmsg = "";
	}

PktDumper::~PktDumper()
	{
	}

void PktDumper::Init()
	{
	Open();
	}

void PktDumper::Done()
	{
	Close();
	}

const std::string& PktDumper::Path() const
	{
	return props.path;
	}

bool PktDumper::IsOpen() const
	{
	return is_open;
	}

double PktDumper::OpenTime() const
	{
	return is_open ? props.open_time : 0;
	}

bool PktDumper::IsError() const
	{
	return errmsg.size();
	}

const char* PktDumper::ErrorMsg() const
	{
	return errmsg.size() ? errmsg.c_str() : 0;
	}

int PktDumper::HdrSize() const
	{
	return is_open ? props.hdr_size : -1;
	}

void PktDumper::Opened(const Properties& arg_props)
	{
	is_open = true;
	props = arg_props;
	DBG_LOG(DBG_PKTIO, "Opened dumper %s", props.path.c_str());
	}

void PktDumper::Closed()
	{
	is_open = false;
	DBG_LOG(DBG_PKTIO, "Closed dumper %s", props.path.c_str());
	props.path = "";
	}

void PktDumper::Error(const std::string& msg)
	{
	errmsg = msg;

	DBG_LOG(DBG_PKTIO, "Error with dumper %s: %s",
		IsOpen() ? props.path.c_str() : "<not open>",
		msg.c_str());
	}
