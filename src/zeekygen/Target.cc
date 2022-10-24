// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeekygen/Target.h"

#include <fts.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <regex>

#include "zeek/Reporter.h"
#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/plugin/Manager.h"
#include "zeek/util.h"
#include "zeek/zeekygen/IdentifierInfo.h"
#include "zeek/zeekygen/Manager.h"
#include "zeek/zeekygen/PackageInfo.h"
#include "zeek/zeekygen/ScriptInfo.h"

using namespace std;

namespace zeek::zeekygen::detail
	{

static void write_plugin_section_heading(FILE* f, const plugin::Plugin* p)
	{
	const string& name = p->Name();

	// A label-safe version of the plugin name: replace _ and : with -, turn
	// sequences of - into single ones, and make lower-case. Example:
	// "Zeek::IEEE802_11" -> "zeek-ieee802-11".
	auto flags = std::regex_constants::match_any;
	string label_name = std::regex_replace(name, std::regex("[_:]"), "-", flags);
	label_name = std::regex_replace(label_name, std::regex("-+"), "-", flags);
	label_name = zeek::util::strtolower(label_name);

	fprintf(f, ".. _plugin-%s:\n\n", label_name.c_str());

	fprintf(f, "%s\n", name.c_str());
	for ( size_t i = 0; i < name.size(); ++i )
		fprintf(f, "-");
	fprintf(f, "\n\n");

	fprintf(f, "%s\n\n", p->Description().c_str());
	}

static void write_analyzer_component(FILE* f, const analyzer::Component* c)
	{
	const auto& atag = analyzer_mgr->GetTagType();
	string tag = util::fmt("ANALYZER_%s", c->CanonicalName().c_str());

	if ( atag->Lookup("Analyzer", tag.c_str()) < 0 )
		reporter->InternalError("missing analyzer tag for %s", tag.c_str());

	fprintf(f, ":zeek:enum:`Analyzer::%s`\n\n", tag.c_str());
	}

static void write_analyzer_component(FILE* f, const packet_analysis::Component* c)
	{
	const auto& atag = packet_mgr->GetTagType();
	string tag = util::fmt("ANALYZER_%s", c->CanonicalName().c_str());

	if ( atag->Lookup("PacketAnalyzer", tag.c_str()) < 0 )
		reporter->InternalError("missing packet analyzer tag for %s", tag.c_str());

	fprintf(f, ":zeek:enum:`PacketAnalyzer::%s`\n\n", tag.c_str());
	}

static void write_analyzer_component(FILE* f, const file_analysis::Component* c)
	{
	const auto& atag = file_mgr->GetTagType();
	string tag = util::fmt("ANALYZER_%s", c->CanonicalName().c_str());

	if ( atag->Lookup("Files", tag.c_str()) < 0 )
		reporter->InternalError("missing analyzer tag for %s", tag.c_str());

	fprintf(f, ":zeek:enum:`Files::%s`\n\n", tag.c_str());
	}

static void write_plugin_components(FILE* f, const plugin::Plugin* p)
	{
	plugin::Plugin::component_list components = p->Components();

	fprintf(f, "Components\n");
	fprintf(f, "++++++++++\n\n");

	for ( const auto& component : components )
		{
		switch ( component->Type() )
			{
			case plugin::component::ANALYZER:
				{
				const analyzer::Component* c = dynamic_cast<const analyzer::Component*>(component);

				if ( c )
					write_analyzer_component(f, c);
				else
					reporter->InternalError("component type mismatch");
				}
				break;

			case plugin::component::PACKET_ANALYZER:
				{
				const packet_analysis::Component* c =
					dynamic_cast<const packet_analysis::Component*>(component);

				if ( c )
					write_analyzer_component(f, c);
				else
					reporter->InternalError("component type mismatch");
				}
				break;

			case plugin::component::FILE_ANALYZER:
				{
				const auto* c = dynamic_cast<const file_analysis::Component*>(component);

				if ( c )
					write_analyzer_component(f, c);
				else
					reporter->InternalError("component type mismatch");
				}
				break;

			case plugin::component::READER:
				reporter->InternalError("docs for READER component unimplemented");

			case plugin::component::WRITER:
				reporter->InternalError("docs for WRITER component unimplemented");

			default:
				reporter->InternalError("docs for unknown component unimplemented");
			}
		}
	}

static void write_plugin_bif_items(FILE* f, const plugin::Plugin* p, plugin::BifItem::Type t,
                                   const string& heading)
	{
	plugin::Plugin::bif_item_list bifitems = p->BifItems();
	plugin::Plugin::bif_item_list::iterator it = bifitems.begin();

	while ( it != bifitems.end() )
		{
		if ( it->GetType() != t )
			it = bifitems.erase(it);
		else
			++it;
		}

	if ( bifitems.empty() )
		return;

	fprintf(f, "%s\n", heading.c_str());
	for ( size_t i = 0; i < heading.size(); ++i )
		fprintf(f, "+");
	fprintf(f, "\n\n");

	for ( it = bifitems.begin(); it != bifitems.end(); ++it )
		{
		IdentifierInfo* doc = zeek::detail::zeekygen_mgr->GetIdentifierInfo(it->GetID());

		if ( doc )
			fprintf(f, "%s\n\n", doc->ReStructuredText().c_str());
		else
			reporter->InternalWarning("Zeekygen ID lookup failed: %s\n", it->GetID().c_str());
		}
	}

static void WriteAnalyzerTagDefn(FILE* f, const string& module)
	{
	string tag_id = module + "::Tag";

	IdentifierInfo* doc = zeek::detail::zeekygen_mgr->GetIdentifierInfo(tag_id);

	if ( ! doc )
		reporter->InternalError("Zeekygen failed analyzer tag lookup: %s", tag_id.c_str());

	fprintf(f, "%s\n", doc->ReStructuredText().c_str());
	}

static bool ComponentsMatch(const plugin::Plugin* p, plugin::component::Type t,
                            bool match_empty = false)
	{
	plugin::Plugin::component_list components = p->Components();
	plugin::Plugin::component_list::const_iterator it;

	if ( components.empty() )
		return match_empty;

	for ( it = components.begin(); it != components.end(); ++it )
		if ( (*it)->Type() != t )
			return false;

	return true;
	}

template <class T> static vector<T*> filter_matches(const vector<Info*>& from, Target* t)
	{
	vector<T*> rval;

	for ( size_t i = 0; i < from.size(); ++i )
		{
		T* d = dynamic_cast<T*>(from[i]);

		if ( ! d )
			continue;

		if ( t->MatchesPattern(d) )
			{
			DBG_LOG(DBG_ZEEKYGEN, "'%s' matched pattern for target '%s'", d->Name().c_str(),
			        t->Name().c_str());
			rval.push_back(d);
			}
		}

	return rval;
	}

TargetFile::TargetFile(const string& arg_name) : name(arg_name), f()
	{
	if ( name.find('/') != string::npos )
		{
		string dir = util::SafeDirname(name).result;

		if ( ! util::detail::ensure_intermediate_dirs(dir.c_str()) )
			reporter->FatalError("Zeekygen failed to make dir %s", dir.c_str());
		}

	f = fopen(name.c_str(), "w");

	if ( ! f )
		reporter->FatalError("Zeekygen failed to open '%s' for writing: %s", name.c_str(),
		                     strerror(errno));
	}

TargetFile::~TargetFile()
	{
	if ( f )
		fclose(f);

	DBG_LOG(DBG_ZEEKYGEN, "Wrote out-of-date target '%s'", name.c_str());
	}

Target::Target(const string& arg_name, const string& arg_pattern)
	: name(arg_name), pattern(arg_pattern), prefix()
	{
	size_t pos = pattern.find('*');

	if ( pos == 0 || pos == string::npos )
		return;

	prefix = pattern.substr(0, pos);
	}

bool Target::MatchesPattern(Info* info) const
	{
	if ( pattern == "*" )
		return true;

	if ( prefix.empty() )
		return info->Name() == pattern;

	return ! strncmp(info->Name().c_str(), prefix.c_str(), prefix.size());
	}

void AnalyzerTarget::DoFindDependencies(const std::vector<Info*>& infos)
	{
	// TODO: really should add to dependency list the tag type's ID and
	// all bif items for matching analyzer plugins, but that's all dependent
	// on the Zeek binary itself, so I'm cheating.
	}

void AnalyzerTarget::DoGenerate() const
	{
	if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), vector<Info*>()) )
		return;

	if ( Pattern() != "*" )
		reporter->InternalWarning("Zeekygen only implements analyzer target"
		                          " pattern '*'");

	TargetFile file(Name());
	CreateAnalyzerDoc(file.f);
	}

void ProtoAnalyzerTarget::DoCreateAnalyzerDoc(FILE* f) const
	{
	fprintf(f, "Protocol Analyzers\n");
	fprintf(f, "==================\n\n");

	WriteAnalyzerTagDefn(f, "Analyzer");
	WriteAnalyzerTagDefn(f, "AllAnalyzers");

	plugin::Manager::plugin_list plugins = plugin_mgr->ActivePlugins();
	plugin::Manager::plugin_list::const_iterator it;

	for ( it = plugins.begin(); it != plugins.end(); ++it )
		{
		if ( ! ComponentsMatch(*it, plugin::component::ANALYZER, true) )
			continue;

		write_plugin_section_heading(f, *it);
		write_plugin_components(f, *it);
		write_plugin_bif_items(f, *it, plugin::BifItem::CONSTANT, "Options/Constants");
		write_plugin_bif_items(f, *it, plugin::BifItem::GLOBAL, "Globals");
		write_plugin_bif_items(f, *it, plugin::BifItem::TYPE, "Types");
		write_plugin_bif_items(f, *it, plugin::BifItem::EVENT, "Events");
		write_plugin_bif_items(f, *it, plugin::BifItem::FUNCTION, "Functions");
		}
	}

void PacketAnalyzerTarget::DoCreateAnalyzerDoc(FILE* f) const
	{
	fprintf(f, "Packet Analyzers\n");
	fprintf(f, "================\n\n");

	WriteAnalyzerTagDefn(f, "PacketAnalyzer");

	plugin::Manager::plugin_list plugins = plugin_mgr->ActivePlugins();
	plugin::Manager::plugin_list::const_iterator it;

	for ( it = plugins.begin(); it != plugins.end(); ++it )
		{
		if ( ! ComponentsMatch(*it, plugin::component::PACKET_ANALYZER) )
			continue;

		write_plugin_section_heading(f, *it);
		write_plugin_components(f, *it);
		write_plugin_bif_items(f, *it, plugin::BifItem::CONSTANT, "Options/Constants");
		write_plugin_bif_items(f, *it, plugin::BifItem::GLOBAL, "Globals");
		write_plugin_bif_items(f, *it, plugin::BifItem::TYPE, "Types");
		write_plugin_bif_items(f, *it, plugin::BifItem::EVENT, "Events");
		write_plugin_bif_items(f, *it, plugin::BifItem::FUNCTION, "Functions");
		}
	}

void FileAnalyzerTarget::DoCreateAnalyzerDoc(FILE* f) const
	{
	fprintf(f, "File Analyzers\n");
	fprintf(f, "==============\n\n");

	WriteAnalyzerTagDefn(f, "Files");

	plugin::Manager::plugin_list plugins = plugin_mgr->ActivePlugins();
	plugin::Manager::plugin_list::const_iterator it;

	for ( it = plugins.begin(); it != plugins.end(); ++it )
		{
		if ( ! ComponentsMatch(*it, plugin::component::FILE_ANALYZER) )
			continue;

		write_plugin_section_heading(f, *it);
		write_plugin_components(f, *it);
		write_plugin_bif_items(f, *it, plugin::BifItem::CONSTANT, "Options/Constants");
		write_plugin_bif_items(f, *it, plugin::BifItem::GLOBAL, "Globals");
		write_plugin_bif_items(f, *it, plugin::BifItem::TYPE, "Types");
		write_plugin_bif_items(f, *it, plugin::BifItem::EVENT, "Events");
		write_plugin_bif_items(f, *it, plugin::BifItem::FUNCTION, "Functions");
		}
	}

void PackageTarget::DoFindDependencies(const vector<Info*>& infos)
	{
	pkg_deps = filter_matches<PackageInfo>(infos, this);

	if ( pkg_deps.empty() )
		reporter->FatalError("No match for Zeekygen target '%s' pattern '%s'", Name().c_str(),
		                     Pattern().c_str());

	for ( size_t i = 0; i < infos.size(); ++i )
		{
		ScriptInfo* script = dynamic_cast<ScriptInfo*>(infos[i]);

		if ( ! script )
			continue;

		for ( size_t j = 0; j < pkg_deps.size(); ++j )
			{
			if ( strncmp(script->Name().c_str(), pkg_deps[j]->Name().c_str(),
			             pkg_deps[j]->Name().size()) )
				continue;

			DBG_LOG(DBG_ZEEKYGEN, "Script %s associated with package %s", script->Name().c_str(),
			        pkg_deps[j]->Name().c_str());
			pkg_manifest[pkg_deps[j]].push_back(script);
			script_deps.push_back(script);
			}
		}
	}

void PackageTarget::DoGenerate() const
	{
	if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), script_deps) &&
	     zeek::detail::zeekygen_mgr->IsUpToDate(Name(), pkg_deps) )
		return;

	TargetFile file(Name());

	fprintf(file.f, ":orphan:\n\n");

	for ( manifest_t::const_iterator it = pkg_manifest.begin(); it != pkg_manifest.end(); ++it )
		{
		string header = util::fmt("Package: %s", it->first->Name().c_str());
		header += "\n" + string(header.size(), '=');

		fprintf(file.f, "%s\n\n", header.c_str());

		vector<string> readme = it->first->GetReadme();

		for ( size_t i = 0; i < readme.size(); ++i )
			fprintf(file.f, "%s\n", readme[i].c_str());

		fprintf(file.f, "\n");

		for ( size_t i = 0; i < it->second.size(); ++i )
			{
			fprintf(file.f, ":doc:`/scripts/%s`\n\n", it->second[i]->Name().c_str());

			vector<string> cmnts = it->second[i]->GetComments();

			for ( size_t j = 0; j < cmnts.size(); ++j )
				fprintf(file.f, "   %s\n", cmnts[j].c_str());

			fprintf(file.f, "\n");
			}
		}
	}

void PackageIndexTarget::DoFindDependencies(const vector<Info*>& infos)
	{
	pkg_deps = filter_matches<PackageInfo>(infos, this);

	if ( pkg_deps.empty() )
		reporter->FatalError("No match for Zeekygen target '%s' pattern '%s'", Name().c_str(),
		                     Pattern().c_str());
	}

void PackageIndexTarget::DoGenerate() const
	{
	if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), pkg_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < pkg_deps.size(); ++i )
		fprintf(file.f, "%s\n", pkg_deps[i]->ReStructuredText().c_str());
	}

void ScriptTarget::DoFindDependencies(const vector<Info*>& infos)
	{
	script_deps = filter_matches<ScriptInfo>(infos, this);

	if ( script_deps.empty() )
		reporter->FatalError("No match for Zeekygen target '%s' pattern '%s'", Name().c_str(),
		                     Pattern().c_str());

	if ( ! IsDir() )
		return;

	for ( size_t i = 0; i < script_deps.size(); ++i )
		{
		if ( util::detail::is_package_loader(script_deps[i]->Name()) )
			{
			string pkg_dir = util::SafeDirname(script_deps[i]->Name()).result;
			string target_file = Name() + pkg_dir + "/index.rst";
			Target* t = new PackageTarget(target_file, pkg_dir);
			t->FindDependencies(infos);
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

	char* dir_copy = util::copy_string(dir.c_str());
	char** scan_path = new char*[2];
	scan_path[0] = dir_copy;
	scan_path[1] = NULL;

	FTS* fts = fts_open(scan_path, FTS_NOCHDIR, 0);

	if ( ! fts )
		{
		reporter->Error("fts_open failure: %s", strerror(errno));
		delete[] scan_path;
		delete[] dir_copy;
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

	delete[] scan_path;
	delete[] dir_copy;
	return rval;
	}

void ScriptTarget::DoGenerate() const
	{
	if ( IsDir() )
		{
		// Target name is a dir, matching scripts are written within that dir
		// with a dir tree that parallels the script's ZEEKPATH location.

		set<string> targets;
		vector<string> dir_contents = dir_contents_recursive(Name());

		for ( size_t i = 0; i < script_deps.size(); ++i )
			{
			string target_filename = Name() + script_deps[i]->Name() + ".rst";
			targets.insert(target_filename);
			vector<ScriptInfo*> dep;
			dep.push_back(script_deps[i]);

			if ( zeek::detail::zeekygen_mgr->IsUpToDate(target_filename, dep) )
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
				reporter->Warning("Failed to unlink %s: %s", f.c_str(), strerror(errno));

			DBG_LOG(DBG_ZEEKYGEN, "Delete stale script file %s", f.c_str());
			}

		return;
		}

	// Target is a single file, all matching scripts get written there.

	if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), script_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < script_deps.size(); ++i )
		fprintf(file.f, "%s\n", script_deps[i]->ReStructuredText().c_str());
	}

void ScriptSummaryTarget::DoGenerate() const
	{
	if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), script_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < script_deps.size(); ++i )
		{
		ScriptInfo* d = dynamic_cast<ScriptInfo*>(script_deps[i]);

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
	if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), script_deps) )
		return;

	TargetFile file(Name());

	fprintf(file.f, ".. toctree::\n");
	fprintf(file.f, "   :maxdepth: 1\n\n");

	for ( size_t i = 0; i < script_deps.size(); ++i )
		{
		ScriptInfo* d = dynamic_cast<ScriptInfo*>(script_deps[i]);

		if ( ! d )
			continue;

		fprintf(file.f, "   %s </scripts/%s>\n", d->Name().c_str(), d->Name().c_str());
		}
	}

void IdentifierTarget::DoFindDependencies(const vector<Info*>& infos)
	{
	id_deps = filter_matches<IdentifierInfo>(infos, this);

	if ( id_deps.empty() )
		reporter->FatalError("No match for Zeekygen target '%s' pattern '%s'", Name().c_str(),
		                     Pattern().c_str());
	}

void IdentifierTarget::DoGenerate() const
	{
	if ( zeek::detail::zeekygen_mgr->IsUpToDate(Name(), id_deps) )
		return;

	TargetFile file(Name());

	for ( size_t i = 0; i < id_deps.size(); ++i )
		fprintf(file.f, "%s\n\n", id_deps[i]->ReStructuredText().c_str());
	}

	} // namespace zeek::zeekygen::detail
