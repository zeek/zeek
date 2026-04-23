// See the file "COPYING" in the main distribution directory for copyright.

// Zeek plugin that serves script content from in-memory ZIP archives via the
// HookLoadFileExtended plugin hook.  The actual ZIP I/O is delegated to
// ZipScriptProvider; this plugin simply bridges between the provider and the
// Zeek script-loading pipeline.

#include "zeek/ZipScriptProvider.h"
#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::detail::Zeek_ZipScripts {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        EnableHook(HOOK_LOAD_FILE_EXT, 0);

        zeek::plugin::Configuration config;
        config.name = "Zeek::ZipScripts";
        config.description = "Loads Zeek scripts from in-memory ZIP archives";
        return config;
    }

    std::pair<int, std::optional<std::string>> HookLoadFileExtended(const LoadType type, const std::string& file,
                                                                    const std::string& resolved) override {
        if ( type != SCRIPT )
            return {-1, std::nullopt};

        auto* zsp = util::ZipScriptProvider::GetInstance();
        if ( ! zsp )
            return {-1, std::nullopt};

        // Use the resolved path when available (set by find_relative_script_file
        // via the can_read/is_dir hooks in util.cc).  Fall back to the raw @load
        // argument for ZIPs loaded without a mount root.
        std::string zip_path;
        if ( ! resolved.empty() )
            zip_path = util::ZipScriptProvider::NormalizePath(resolved);
        else {
            // No resolved path — try the raw filename directly in the ZIP.
            // This is a best-effort fallback for ZIPs without mount roots;
            // @DIR, @FILENAME, and relative @load may not work correctly
            // since file_path stays empty in scan.l.
            zip_path = util::ZipScriptProvider::NormalizePath(file);
            if ( ! zsp->HasFile(zip_path) ) {
                // Append .zeek extension if not present.
                std::string with_ext = zip_path + ".zeek";
                if ( zsp->HasFile(with_ext) )
                    zip_path = with_ext;
                else {
                    // Try as package directory.
                    std::string pkg = zip_path + "/__load__.zeek";
                    if ( zsp->HasFile(pkg) )
                        zip_path = pkg;
                }
            }
        }

        auto content = zsp->ReadFile(zip_path);
        if ( ! content )
            return {-1, std::nullopt};

        return {1, std::move(*content)};
    }

} plugin;

} // namespace zeek::plugin::detail::Zeek_ZipScripts
