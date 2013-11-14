#ifndef BROXYGEN_MANAGER_H
#define BROXYGEN_MANAGER_H

#include "Configuration.h"
#include "Document.h"

#include "Reporter.h"
#include "ID.h"
#include "Type.h"
#include "Val.h"

#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <sys/stat.h>

namespace broxygen {

// TODO: documentation...

template<class T>
struct DocumentMap {
	typedef std::map<std::string, T*> map_type;

	T* GetDocument(const std::string& name) const
		{
		typename map_type::const_iterator it = map.find(name);
		return it == map.end() ? 0 : it->second;
		}

	map_type map;
};

class Manager {

public:

	Manager(const std::string& config, const std::string& bro_command);

	~Manager();

	void InitPreScript();

	void InitPostScript();

	void GenerateDocs() const;

	void File(const std::string& path);

	void ScriptDependency(const std::string& path, const std::string& dep);

	void ModuleUsage(const std::string& path, const std::string& module);

	void StartType(ID* id);

	void Identifier(ID* id);

	void RecordField(const ID* id, const TypeDecl* field,
	                 const std::string& path);

	void Redef(const ID* id, const std::string& path);

	void SummaryComment(const std::string& path, const std::string& comment);

	void PreComment(const std::string& comment);

	void PostComment(const std::string& comment,
	                 const std::string& identifier_hint = "");

	std::string GetEnumTypeName(const std::string& id) const;

	IdentifierDocument* GetIdentifierDoc(const std::string& name) const
	    { return identifiers.GetDocument(name); }

	ScriptDocument* GetScriptDoc(const std::string& name) const
	    { return scripts.GetDocument(name); }

	PackageDocument* GetPackageDoc(const std::string& name) const
	    { return packages.GetDocument(name); }

	template <class T>
	bool IsUpToDate(const std::string& target_file,
	                const std::vector<T*>& dependencies) const;

private:

	typedef std::vector<std::string> comment_buffer_t;
	typedef std::map<std::string, comment_buffer_t> comment_buffer_map_t;

	IdentifierDocument* CreateIdentifierDoc(ID* id, ScriptDocument* script);

	bool disabled;
	comment_buffer_t comment_buffer; // For whatever next identifier that comes in.
	comment_buffer_map_t comment_buffer_map; // For a particular identifier.
	DocumentMap<PackageDocument> packages;
	DocumentMap<ScriptDocument> scripts;
	DocumentMap<IdentifierDocument> identifiers;
	std::vector<Document*> all_docs;
	IdentifierDocument* last_identifier_seen;
	IdentifierDocument* incomplete_type;
	std::map<std::string, std::string> enum_mappings;
	Config config;
	time_t bro_mtime;
};

template <class T>
bool Manager::IsUpToDate(const string& target_file,
                         const vector<T*>& dependencies) const
	{
	struct stat s;

	if ( stat(target_file.c_str(), &s) < 0 )
		{
		if ( errno == ENOENT )
			// Doesn't exist.
			return false;

		reporter->InternalError("Broxygen failed to stat target file '%s': %s",
		                        target_file.c_str(), strerror(errno));
		}

	if ( difftime(bro_mtime, s.st_mtime) > 0 )
		return false;

	if ( difftime(config.GetModificationTime(), s.st_mtime) > 0 )
		return false;

	for ( size_t i = 0; i < dependencies.size(); ++i )
		if ( difftime(dependencies[i]->GetModificationTime(), s.st_mtime) > 0 )
			return false;

	return true;
	}

} // namespace broxygen

extern broxygen::Manager* broxygen_mgr;

#endif
