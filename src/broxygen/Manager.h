#ifndef BROXYGEN_MANAGER_H
#define BROXYGEN_MANAGER_H

#include "Document.h"
#include "ID.h"
#include "Type.h"

#include <string>
#include <map>
#include <set>
#include <vector>

namespace broxygen {

// TODO: documentation...
// TODO: optimize parse time... maybe an env. option to disable doc collection?

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

	void Identifier(ID* id);

	void RecordField(const ID* id, const TypeDecl* field,
	                 const std::string& path);

	void Redef(const ID* id, const std::string& path);

	void SummaryComment(const std::string& path, const std::string& comment);

	void PreComment(const std::string& comment);

	void PostComment(const std::string& comment);

private:

	typedef std::vector<std::string> CommentBuffer;
	typedef std::map<std::string, PackageDocument*> PackageMap;
	typedef std::map<std::string, ScriptDocument*> ScriptMap;
	typedef std::map<std::string, IdentifierDocument*> IdentifierMap;
	typedef std::set<Document*> DocSet;

	void RegisterDoc(Document* d);

	CommentBuffer comment_buffer;
	PackageMap packages;
	ScriptMap scripts;
	IdentifierMap identifiers;
	DocSet all_docs;
	Document* last_doc_seen;
	IdentifierDocument* incomplete_type;
};

} // namespace broxygen

extern broxygen::Manager* broxygen_mgr;

#endif
