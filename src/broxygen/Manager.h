#ifndef BROXYGEN_MANAGER_H
#define BROXYGEN_MANAGER_H

#include <string>

#include "ID.h"
#include "Type.h"

namespace broxygen {

class Manager {

public:

	Manager(const std::string& config);

	void GenerateDocs() const;

	void File(const std::string& path);

	void ScriptDependency(const std::string& path, const std::string& dep);

	void ModuleUsage(const std::string& path, const std::string& module);

	void Identifier(const ID* id);

	void RecordField(const ID* id, const TypeDecl* field,
	                 const std::string& path);

	void Redef(const ID* id, const std::string& path);

	void SummaryComment(const std::string& path, const std::string& comment);

	void PreComment(const std::string& comment);

	void PostComment(const std::string& comment);
};

} // namespace broxygen

extern broxygen::Manager* broxygen_mgr;

#endif
