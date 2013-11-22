#include "Configuration.h"
#include "Manager.h"

#include "util.h"
#include "Reporter.h"

#include <fstream>
#include <vector>
#include <algorithm>
#include <map>
#include <cstdio>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <unistd.h>

using namespace broxygen;
using namespace std;

typedef map<string, Target::factory_fn> target_factory_map;

static target_factory_map create_target_factory_map()
	{
	target_factory_map rval;
	rval["package_index"] =  &PackageIndexTarget::Instantiate;
	rval["package"] =        &PackageTarget::Instantiate;
	rval["proto_analyzer"] = &ProtoAnalyzerTarget::Instantiate;
	rval["file_analyzer"] =  &FileAnalyzerTarget::Instantiate;
	rval["script_summary"] = &ScriptSummaryTarget::Instantiate;
	rval["script_index"] =   &ScriptIndexTarget::Instantiate;
	rval["script"] =         &ScriptTarget::Instantiate;
	rval["identifier"] =     &IdentifierTarget::Instantiate;
	return rval;
	}

static target_factory_map target_instantiators = create_target_factory_map();

struct TargetFile {
	TargetFile(const string& arg_name)
		: name(arg_name), f()
		{
		if ( name.find('/') != string::npos )
			{
			string dir = SafeDirname(name).result;

			if ( ! ensure_intermediate_dirs(dir.c_str()) )
				reporter->FatalError("Broxygen failed to make dir %s",
				                     dir.c_str());
			}

		f = fopen(name.c_str(), "w");

		if ( ! f )
			reporter->FatalError("Broxygen failed to open '%s' for writing: %s",
			                     name.c_str(), strerror(errno));
		}

	~TargetFile()
		{
		if ( f )
			fclose(f);

		DBG_LOG(DBG_BROXYGEN, "Wrote out-of-date target '%s'", name.c_str());
		}

	string name;
	FILE* f;
};

template<class T>
static vector<T*> filter_matching_docs(const vector<Document*>& from, Target* t)
	{
	vector<T*> rval;

	for ( size_t i = 0; i < from.size(); ++i )
		{
		T* d = dynamic_cast<T*>(from[i]);

		if ( ! d )
			continue;

		if ( t->MatchesPattern(d) )
			{
			DBG_LOG(DBG_BROXYGEN, "Doc '%s' matched pattern for target '%s'",
			        d->Name().c_str(), t->Name().c_str());
			rval.push_back(d);
			}
		}

	return rval;
	}

Target::Target(const string& arg_name, const string& arg_pattern)
    : name(arg_name), pattern(arg_pattern), prefix()
	{
	size_t pos = pattern.find('*');

	if ( pos == 0 || pos == string::npos )
		return;

	prefix = pattern.substr(0, pos);
	}

bool Target::MatchesPattern(Document* doc) const
	{
	if ( pattern == "*" )
		return true;

	if ( prefix.empty() )
		return doc->Name() == pattern;

	return ! strncmp(doc->Name().c_str(), prefix.c_str(), prefix.size());
	}

void AnalyzerTarget::DoFindDependencies(const std::vector<Document *>& docs)
	{
	// TODO: really should add to dependency list the tag type's ID and
	// all bif items for matching analyzer plugins, but that's all dependent
	// on the bro binary itself, so I'm cheating.
	}

void AnalyzerTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), vector<Document*>()) )
		return;

	if ( Pattern() != "*" )
		reporter->InternalWarning("Broxygen only implements analyzer target"
		                          " pattern '*'");

	TargetFile file(Name());
	doc_creator_callback(file.f);
	}

void PackageTarget::DoFindDependencies(const vector<Document*>& docs)
	{
	pkg_deps = filter_matching_docs<PackageDocument>(docs, this);

	if ( pkg_deps.empty() )
		reporter->FatalError("No match for Broxygen target '%s' pattern '%s'",
		                     Name().c_str(), Pattern().c_str());

	for ( size_t i = 0; i < docs.size(); ++i )
		{
		ScriptDocument* script = dynamic_cast<ScriptDocument*>(docs[i]);

		if ( ! script )
			continue;

		for ( size_t j = 0; j < pkg_deps.size(); ++j )
			{
			if ( strncmp(script->Name().c_str(), pkg_deps[j]->Name().c_str(),
			             pkg_deps[j]->Name().size()))
				continue;

			DBG_LOG(DBG_BROXYGEN, "Script %s associated with package %s",
			        script->Name().c_str(), pkg_deps[j]->Name().c_str());
			pkg_manifest[pkg_deps[j]].push_back(script);
			script_deps.push_back(script);
			}
		}
	}

void PackageTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), script_deps) &&
	     broxygen_mgr->IsUpToDate(Name(), pkg_deps) )
		return;

	TargetFile file(Name());

	fprintf(file.f, ":orphan:\n\n");

	for ( manifest_t::const_iterator it = pkg_manifest.begin();
	      it != pkg_manifest.end(); ++it )
		{
		string header = fmt("Package: %s", it->first->Name().c_str());
		header += "\n" + string(header.size(), '=');

		fprintf(file.f, "%s\n\n", header.c_str());

		vector<string> readme = it->first->GetReadme();

		for ( size_t i = 0; i < readme.size(); ++i )
			fprintf(file.f, "%s\n", readme[i].c_str());

		fprintf(file.f, "\n");

		for ( size_t i = 0; i < it->second.size(); ++i )
			{
			fprintf(file.f, ":doc:`/scripts/%s`\n",
			        it->second[i]->Name().c_str());

			vector<string> cmnts = it->second[i]->GetComments();

			for ( size_t j = 0; j < cmnts.size(); ++j )
				fprintf(file.f, "   %s\n", cmnts[j].c_str());

			fprintf(file.f, "\n");
			}
		}
	}

void PackageIndexTarget::DoFindDependencies(const vector<Document*>& docs)
	{
	pkg_deps = filter_matching_docs<PackageDocument>(docs, this);

	if ( pkg_deps.empty() )
		reporter->FatalError("No match for Broxygen target '%s' pattern '%s'",
		                     Name().c_str(), Pattern().c_str());
	}

void PackageIndexTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), pkg_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < pkg_deps.size(); ++i )
		fprintf(file.f, "%s\n", pkg_deps[i]->ReStructuredText().c_str());
	}

void ScriptTarget::DoFindDependencies(const vector<Document*>& docs)
    {
	script_deps = filter_matching_docs<ScriptDocument>(docs, this);

	if ( script_deps.empty() )
		reporter->FatalError("No match for Broxygen target '%s' pattern '%s'",
		                     Name().c_str(), Pattern().c_str());

	if ( ! IsDir() )
		return;

	for ( size_t i = 0; i < script_deps.size(); ++i )
		{
		if ( SafeBasename(script_deps[i]->Name()).result == PACKAGE_LOADER )
			{
			string pkg_dir = SafeDirname(script_deps[i]->Name()).result;
			string target_file = Name() + pkg_dir + "/index.rst";
			Target* t = PackageTarget::Instantiate(target_file, pkg_dir);
			t->FindDependencies(docs);
			pkg_deps.push_back(t);
			}
		}
	}

vector<string> dir_contents_recursive(string dir)
	{
	vector<string> rval;
	struct stat st;

	if ( stat(dir.c_str(), &st) < 0 && errno == ENOENT )
		return rval;

	while ( dir[dir.size() - 1] == '/' )
		dir.erase(dir.size() - 1, 1);

	char* dir_copy = copy_string(dir.c_str());
	char** scan_path = new char*[2];
	scan_path[0] = dir_copy;
	scan_path[1] = 0;

	FTS* fts = fts_open(scan_path, FTS_NOCHDIR, 0);

	if ( ! fts )
		{
		reporter->Error("fts_open failure: %s", strerror(errno));
		delete [] scan_path;
		delete [] dir_copy;
		return rval;
		}

	FTSENT* n;

	while ( (n = fts_read(fts)) )
		{
		if ( n->fts_info & FTS_F )
			rval.push_back(n->fts_path);
		}

	if ( errno )
		reporter->Error("fts_read failure: %s", strerror(errno));

	if ( fts_close(fts) < 0 )
		reporter->Error("fts_close failure: %s", strerror(errno));

	delete [] scan_path;
	delete [] dir_copy;
	return rval;
	}

void ScriptTarget::DoGenerate() const
    {
	if ( IsDir() )
		{
		// Target name is a dir, matching scripts are written within that dir
		// with a dir tree that parallels the script's BROPATH location.

		set<string> targets;
		vector<string> dir_contents = dir_contents_recursive(Name());

		for ( size_t i = 0; i < script_deps.size(); ++i )
			{
			string target_filename = Name() + script_deps[i]->Name() + ".rst";
			targets.insert(target_filename);
			vector<ScriptDocument*> dep;
			dep.push_back(script_deps[i]);

			if ( broxygen_mgr->IsUpToDate(target_filename, dep) )
				continue;

			TargetFile file(target_filename);

			fprintf(file.f, "%s\n", script_deps[i]->ReStructuredText().c_str());
			}

		for ( size_t i = 0; i < pkg_deps.size(); ++i )
			{
			targets.insert(pkg_deps[i]->Name());
			pkg_deps[i]->Generate();
			}

		for ( size_t i = 0; i < dir_contents.size(); ++i )
			{
			string f = dir_contents[i];

			if ( targets.find(f) != targets.end() )
				continue;

			if ( unlink(f.c_str()) < 0 )
				reporter->Warning("Failed to unlink %s: %s", f.c_str(),
				                  strerror(errno));

			DBG_LOG(DBG_BROXYGEN, "Delete stale script file %s", f.c_str());
			}

		return;
		}

	// Target is a single file, all matching scripts get written there.

	if ( broxygen_mgr->IsUpToDate(Name(), script_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < script_deps.size(); ++i )
		fprintf(file.f, "%s\n", script_deps[i]->ReStructuredText().c_str());
	}

void ScriptSummaryTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), script_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < script_deps.size(); ++i )
		{
		ScriptDocument* d = dynamic_cast<ScriptDocument*>(script_deps[i]);

		if ( ! d )
			continue;

		fprintf(file.f, ":doc:`/scripts/%s`\n", d->Name().c_str());

		vector<string> cmnts = d->GetComments();

		for ( size_t i = 0; i < cmnts.size(); ++i )
			fprintf(file.f, "    %s\n", cmnts[i].c_str());

		fprintf(file.f, "\n");
		}
	}

void ScriptIndexTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), script_deps) )
		return;

	TargetFile file(Name());

	fprintf(file.f, ".. toctree::\n");
	fprintf(file.f, "   :maxdepth: 1\n\n");

	for ( size_t i = 0; i < script_deps.size(); ++i )
		{
		ScriptDocument* d = dynamic_cast<ScriptDocument*>(script_deps[i]);

		if ( ! d )
			continue;

		fprintf(file.f, "   %s </scripts/%s>\n", d->Name().c_str(),
		        d->Name().c_str());
		}
	}

void IdentifierTarget::DoFindDependencies(const vector<Document*>& docs)
	{
	id_deps = filter_matching_docs<IdentifierDocument>(docs, this);

	if ( id_deps.empty() )
		reporter->FatalError("No match for Broxygen target '%s' pattern '%s'",
		                     Name().c_str(), Pattern().c_str());
	}

void IdentifierTarget::DoGenerate() const
	{
	if ( broxygen_mgr->IsUpToDate(Name(), id_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < id_deps.size(); ++i )
		fprintf(file.f, "%s\n\n", id_deps[i]->ReStructuredText().c_str());
	}

Config::Config(const string& arg_file, const string& delim)
	: file(arg_file), targets()
	{
	if ( file.empty() )
		return;

	ifstream f(file.c_str());

	if ( ! f.is_open() )
		reporter->FatalError("failed to open Broxygen config file '%s': %s",
		                     file.c_str(), strerror(errno));

	string line;
	unsigned int line_number = 0;

	while ( getline(f, line) )
		{
		++line_number;
		vector<string> tokens;
		tokenize_string(line, delim, &tokens);
		tokens.erase(remove(tokens.begin(), tokens.end(), ""), tokens.end());

		if ( tokens.empty() )
			// Blank line.
			continue;

		if ( ! tokens[0].empty() && tokens[0][0] == '#' )
			// Comment
			continue;

		if ( tokens.size() != 3 )
			reporter->FatalError("malformed Broxygen target in %s:%u: %s",
			                     file.c_str(), line_number, line.c_str());

		target_factory_map::const_iterator it =
		        target_instantiators.find(tokens[0]);

		if ( it == target_instantiators.end() )
			reporter->FatalError("unkown Broxygen target type: %s",
			                     tokens[0].c_str());

		targets.push_back(it->second(tokens[2], tokens[1]));
		}

	if ( f.bad() )
		reporter->InternalError("error reading Broxygen config file '%s': %s",
		                        file.c_str(), strerror(errno));
	}

Config::~Config()
	{
	for ( size_t i = 0; i < targets.size(); ++i )
		delete targets[i];
	}

void Config::FindDependencies(const vector<Document*>& docs)
	{
	for ( size_t i = 0; i < targets.size(); ++i )
		targets[i]->FindDependencies(docs);
	}

void Config::GenerateDocs() const
	{
	for ( size_t i = 0; i < targets.size(); ++i )
		targets[i]->Generate();
	}

time_t Config::GetModificationTime() const
	{
	struct stat s;

	if ( stat(file.c_str(), &s) < 0 )
		reporter->InternalError("Broxygen can't stat config file %s: %s",
		                        file.c_str(), strerror(errno));

	return s.st_mtime;
	}
