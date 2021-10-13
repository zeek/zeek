// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/script_opt/CPP/HashMgr.h"

#include "zeek/script_opt/CPP/Func.h"
#include "zeek/script_opt/CPP/Util.h"

namespace zeek::detail
	{

using namespace std;

VarMapper compiled_items;

CPPHashManager::CPPHashManager(const char* hash_name_base, bool _append)
	{
	append = _append;

	hash_name = string(hash_name_base) + ".dat";

	if ( append )
		{
		hf_r = fopen(hash_name.c_str(), "r");
		if ( ! hf_r )
			{
			reporter->Error("can't open auxiliary C++ hash file %s for reading", hash_name.c_str());
			exit(1);
			}

		lock_file(hash_name, hf_r);
		LoadHashes(hf_r);
		}

	auto mode = append ? "a" : "w";

	hf_w = fopen(hash_name.c_str(), mode);
	if ( ! hf_w )
		{
		reporter->Error("can't open auxiliary C++ hash file %s for writing", hash_name.c_str());
		exit(1);
		}
	}

CPPHashManager::~CPPHashManager()
	{
	fclose(hf_w);

	if ( hf_r )
		{
		unlock_file(hash_name, hf_r);
		fclose(hf_r);
		}
	}

void CPPHashManager::LoadHashes(FILE* f)
	{
	string key;

	// The hash file format is inefficient but simple to scan.
	// It doesn't appear to pose a bottleneck, so until it does
	// it makes sense for maintainability to keep it dead simple.

	while ( GetLine(f, key) )
		{
		string line;

		RequireLine(f, line);

		p_hash_type hash;

		if ( key == "func" )
			{
			auto func = line;

			RequireLine(f, line);

			if ( sscanf(line.c_str(), "%llu", &hash) != 1 || hash == 0 )
				BadLine(line);

			previously_compiled[hash] = func;
			}

		else if ( key == "global" )
			{
			auto gl = line;

			RequireLine(f, line);

			p_hash_type gl_t_h, gl_v_h;
			if ( sscanf(line.c_str(), "%llu %llu", &gl_t_h, &gl_v_h) != 2 )
				BadLine(line);

			gl_type_hashes[gl] = gl_t_h;
			gl_val_hashes[gl] = gl_v_h;

			// Eat the location info.  It's there just for
			// maintainers to be able to track down peculiarities
			// in the hash file.
			(void)RequireLine(f, line);
			}

		else if ( key == "global-var" )
			{
			auto gl = line;

			RequireLine(f, line);

			int scope;
			if ( sscanf(line.c_str(), "%d", &scope) != 1 )
				BadLine(line);

			gv_scopes[gl] = scope;
			}

		else if ( key == "hash" )
			{
			int index;
			int scope;

			if ( sscanf(line.c_str(), "%llu %d %d", &hash, &index, &scope) != 3 || hash == 0 )
				BadLine(line);

			compiled_items[hash] = CompiledItemPair{index, scope};
			}

		else if ( key == "record" )
			record_type_globals.insert(line);
		else if ( key == "enum" )
			enum_type_globals.insert(line);

		else
			BadLine(line);
		}
	}

void CPPHashManager::RequireLine(FILE* f, string& line)
	{
	if ( ! GetLine(f, line) )
		{
		reporter->Error("missing final %s hash file entry", hash_name.c_str());
		exit(1);
		}
	}

bool CPPHashManager::GetLine(FILE* f, string& line)
	{
	char buf[8192];
	if ( ! fgets(buf, sizeof buf, f) )
		return false;

	int n = strlen(buf);
	if ( n > 0 && buf[n - 1] == '\n' )
		buf[n - 1] = '\0';

	line = buf;
	return true;
	}

void CPPHashManager::BadLine(string& line)
	{
	reporter->Error("bad %s hash file entry: %s", hash_name.c_str(), line.c_str());
	exit(1);
	}

	} // zeek::detail
