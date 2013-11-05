#ifndef BROXYGEN_MANAGER_H
#define BROXYGEN_MANAGER_H

#include "Configuration.h"
#include "Document.h"
#include "ID.h"
#include "Type.h"
#include "Val.h"

#include <string>
#include <vector>
#include <map>

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

	Manager(const std::string& config);

	~Manager();

	void InitPreScript();

	void InitPostScript();

	void GenerateDocs() const;

	void File(const std::string& path);

	void ScriptDependency(const std::string& path, const std::string& dep);

	void ModuleUsage(const std::string& path, const std::string& module);

	void StartType(ID* id);

	void StartRedef(ID* id);

	void Identifier(ID* id);

	void RecordField(const ID* id, const TypeDecl* field,
	                 const std::string& path);

	void Redef(const ID* id, const std::string& path);

	void SummaryComment(const std::string& path, const std::string& comment);

	void PreComment(const std::string& comment);

	void PostComment(const std::string& comment,
	                 const std::string& identifier_hint = "");

	StringVal* GetIdentifierComments(const std::string& name) const;

	StringVal* GetScriptComments(const std::string& name) const;

	StringVal* GetPackageReadme(const std::string& name) const;

	StringVal* GetRecordFieldComments(const std::string& name) const;

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
	Config config;
};

} // namespace broxygen

extern broxygen::Manager* broxygen_mgr;

#endif
