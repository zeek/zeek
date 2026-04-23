// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ZipScriptProvider.h"

#include <zip.h>
#include <algorithm>
#include <filesystem>

namespace zeek::util {

std::unique_ptr<ZipScriptProvider> ZipScriptProvider::instance;

ZipScriptProvider::ZipScriptProvider() = default;

ZipScriptProvider::~ZipScriptProvider() {
    for ( auto& archive : archives ) {
        if ( archive.handle )
            zip_close(archive.handle);
    }
}

bool ZipScriptProvider::AddArchive(const void* data, size_t size, const std::string& mount_root) {
    Archive archive;
    archive.data.assign(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + size);
    archive.mount_root = NormalizePath(mount_root);

    // Ensure mount_root ends with '/' for prefix stripping.
    if ( ! archive.mount_root.empty() && archive.mount_root.back() != '/' )
        archive.mount_root += '/';

    zip_error_t error;
    zip_error_init(&error);

    zip_source_t* src = zip_source_buffer_create(archive.data.data(), archive.data.size(), 0, &error);
    if ( ! src ) {
        zip_error_fini(&error);
        return false;
    }

    archive.handle = zip_open_from_source(src, ZIP_RDONLY, &error);
    if ( ! archive.handle ) {
        zip_source_free(src);
        zip_error_fini(&error);
        return false;
    }

    zip_error_fini(&error);
    archives.push_back(std::move(archive));
    return true;
}

std::string ZipScriptProvider::NormalizePath(const std::string& path) {
    std::string result = path;

    // Convert backslashes to forward slashes.
    std::replace(result.begin(), result.end(), '\\', '/');

    // Use std::filesystem for lexical normalization (collapses . and ..).
    result = std::filesystem::path(result).lexically_normal().string();

    // On Windows, lexically_normal may reintroduce backslashes.
    std::replace(result.begin(), result.end(), '\\', '/');

    // Strip leading "./" if present.
    if ( result.size() >= 2 && result[0] == '.' && result[1] == '/' )
        result = result.substr(2);

    // Strip trailing "/" for file lookups.
    while ( result.size() > 1 && result.back() == '/' )
        result.pop_back();

    return result;
}

bool ZipScriptProvider::HasFile(const std::string& path) const {
    std::string normalized = NormalizePath(path);

    for ( const auto& archive : archives ) {
        std::string zip_path = normalized;

        // Strip mount root prefix if present.
        if ( ! archive.mount_root.empty() && zip_path.size() > archive.mount_root.size() &&
             zip_path.compare(0, archive.mount_root.size(), archive.mount_root) == 0 )
            zip_path = zip_path.substr(archive.mount_root.size());

        if ( zip_name_locate(archive.handle, zip_path.c_str(), 0) >= 0 )
            return true;
    }
    return false;
}

bool ZipScriptProvider::HasDir(const std::string& path) const {
    std::string normalized = NormalizePath(path);

    for ( const auto& archive : archives ) {
        std::string zip_path = normalized;

        // Strip mount root prefix if present.
        if ( ! archive.mount_root.empty() && zip_path.size() > archive.mount_root.size() &&
             zip_path.compare(0, archive.mount_root.size(), archive.mount_root) == 0 )
            zip_path = zip_path.substr(archive.mount_root.size());

        // Ensure trailing slash for directory lookup.
        std::string dirPath = zip_path;
        if ( ! dirPath.empty() && dirPath.back() != '/' )
            dirPath += '/';

        // Check explicit directory entry.
        if ( zip_name_locate(archive.handle, dirPath.c_str(), 0) >= 0 )
            return true;

        // Check implicit directory: any entry starting with "dir/" implies the
        // directory exists (many ZIPs omit explicit directory entries).
        auto numEntries = zip_get_num_entries(archive.handle, 0);
        for ( zip_int64_t i = 0; i < numEntries; ++i ) {
            const char* name = zip_get_name(archive.handle, i, 0);
            if ( name ) {
                std::string entryName(name);
                if ( entryName.size() > dirPath.size() && entryName.compare(0, dirPath.size(), dirPath) == 0 )
                    return true;
            }
        }
    }
    return false;
}

std::optional<std::string> ZipScriptProvider::ReadFile(const std::string& path) const {
    std::string normalized = NormalizePath(path);

    for ( const auto& archive : archives ) {
        std::string zip_path = normalized;

        // Strip mount root prefix if present.
        if ( ! archive.mount_root.empty() && zip_path.size() > archive.mount_root.size() &&
             zip_path.compare(0, archive.mount_root.size(), archive.mount_root) == 0 )
            zip_path = zip_path.substr(archive.mount_root.size());

        zip_int64_t idx = zip_name_locate(archive.handle, zip_path.c_str(), 0);
        if ( idx < 0 )
            continue;

        zip_stat_t st;
        if ( zip_stat_index(archive.handle, idx, 0, &st) != 0 )
            continue;

        zip_file_t* zf = zip_fopen_index(archive.handle, idx, 0);
        if ( ! zf )
            continue;

        std::string content(st.size, '\0');
        zip_uint64_t total = 0;
        while ( total < st.size ) {
            zip_int64_t n = zip_fread(zf, content.data() + total, st.size - total);
            if ( n <= 0 )
                break;
            total += static_cast<zip_uint64_t>(n);
        }
        zip_fclose(zf);

        if ( total != st.size )
            continue;

        return content;
    }

    return std::nullopt;
}

ZipScriptProvider* ZipScriptProvider::GetInstance() { return instance.get(); }

void ZipScriptProvider::SetInstance(std::unique_ptr<ZipScriptProvider> provider) { instance = std::move(provider); }

} // namespace zeek::util

#include <cstring>

#include "zeek/3rdparty/doctest.h"

namespace {

// Helper: create an in-memory ZIP archive with specified entries.
// Returns the raw ZIP bytes, or empty vector on failure.
std::vector<uint8_t> create_test_zip(const std::vector<std::pair<std::string, std::string>>& entries) {
    zip_error_t error;
    zip_error_init(&error);

    zip_source_t* src = zip_source_buffer_create(nullptr, 0, 0, &error);
    if ( ! src ) {
        zip_error_fini(&error);
        return {};
    }

    // Keep the source alive past zip_close() so we can read the result.
    zip_source_keep(src);

    zip_t* za = zip_open_from_source(src, ZIP_TRUNCATE, &error);
    if ( ! za ) {
        zip_source_free(src);
        zip_error_fini(&error);
        return {};
    }
    zip_error_fini(&error);

    for ( const auto& [name, content] : entries ) {
        zip_source_t* file_src = zip_source_buffer(za, content.data(), content.size(), 0);
        if ( ! file_src ) {
            zip_discard(za);
            zip_source_free(src);
            return {};
        }
        if ( zip_file_add(za, name.c_str(), file_src, ZIP_FL_OVERWRITE | ZIP_FL_ENC_UTF_8) < 0 ) {
            zip_source_free(file_src);
            zip_discard(za);
            zip_source_free(src);
            return {};
        }
    }

    // Close finalizes the ZIP into the source buffer.
    zip_close(za);

    // Read back the finalized ZIP from the source.
    zip_source_open(src);
    zip_source_seek(src, 0, SEEK_END);
    auto zip_size = static_cast<size_t>(zip_source_tell(src));
    zip_source_seek(src, 0, SEEK_SET);

    std::vector<uint8_t> result(zip_size);
    zip_source_read(src, result.data(), zip_size);
    zip_source_close(src);
    zip_source_free(src);

    return result;
}

} // anonymous namespace

TEST_SUITE("ZipScriptProvider") {
    using zeek::util::ZipScriptProvider;

    TEST_CASE("NormalizePath basics") {
        // Forward slashes unchanged.
        CHECK(ZipScriptProvider::NormalizePath("foo/bar") == "foo/bar");
        CHECK(ZipScriptProvider::NormalizePath("ndr/main.zeek") == "ndr/main.zeek");

        // Backslash conversion.
        CHECK(ZipScriptProvider::NormalizePath("foo\\bar") == "foo/bar");
        CHECK(ZipScriptProvider::NormalizePath("foo\\bar\\baz.zeek") == "foo/bar/baz.zeek");

        // Collapse . and ..
        CHECK(ZipScriptProvider::NormalizePath("foo/./bar") == "foo/bar");
        CHECK(ZipScriptProvider::NormalizePath("foo/baz/../bar") == "foo/bar");

        // Strip leading ./
        CHECK(ZipScriptProvider::NormalizePath("./foo/bar") == "foo/bar");
        CHECK(ZipScriptProvider::NormalizePath("./foo") == "foo");

        // Strip trailing /
        CHECK(ZipScriptProvider::NormalizePath("foo/bar/") == "foo/bar");

        // Empty and root.
        CHECK(ZipScriptProvider::NormalizePath("") == "");
        CHECK(ZipScriptProvider::NormalizePath(".") == ".");

#ifdef _MSC_VER
        // Windows absolute path.
        CHECK(ZipScriptProvider::NormalizePath("C:\\scripts\\ndr\\main.zeek") == "C:/scripts/ndr/main.zeek");
        CHECK(ZipScriptProvider::NormalizePath("C:\\scripts\\ndr\\..\\main.zeek") == "C:/scripts/main.zeek");
#endif
    }

    TEST_CASE("AddArchive with valid ZIP") {
        auto zip_data = create_test_zip({
            {"test/hello.zeek", "print \"hello\";"},
            {"test/world.zeek", "print \"world\";"},
        });
        REQUIRE(! zip_data.empty());

        ZipScriptProvider provider;
        CHECK(provider.AddArchive(zip_data.data(), zip_data.size()));
    }

    TEST_CASE("AddArchive with invalid data") {
        ZipScriptProvider provider;
        const char* garbage = "this is not a zip file";
        CHECK_FALSE(provider.AddArchive(garbage, strlen(garbage)));
    }

    TEST_CASE("AddArchive with empty buffer") {
        ZipScriptProvider provider;
        // libzip accepts a zero-size buffer as a valid empty archive.
        uint8_t empty = 0;
        CHECK(provider.AddArchive(&empty, 0));
        // But it has no files.
        CHECK_FALSE(provider.HasFile("anything.zeek"));
    }

    TEST_CASE("HasFile") {
        auto zip_data = create_test_zip({
            {"ndr/main.zeek", "# main script"},
            {"ndr/protocols/http.zeek", "# http"},
        });
        REQUIRE(! zip_data.empty());

        ZipScriptProvider provider;
        REQUIRE(provider.AddArchive(zip_data.data(), zip_data.size()));

        CHECK(provider.HasFile("ndr/main.zeek"));
        CHECK(provider.HasFile("ndr/protocols/http.zeek"));
        CHECK_FALSE(provider.HasFile("ndr/nonexistent.zeek"));
        CHECK_FALSE(provider.HasFile("other/file.zeek"));

        // Directories are not files.
        CHECK_FALSE(provider.HasFile("ndr"));
        CHECK_FALSE(provider.HasFile("ndr/"));
    }

    TEST_CASE("HasDir with implicit directories") {
        // ZIP has NO explicit directory entries — only files. HasDir must infer.
        auto zip_data = create_test_zip({
            {"ndr/main.zeek", "# main"},
            {"ndr/protocols/http.zeek", "# http"},
        });
        REQUIRE(! zip_data.empty());

        ZipScriptProvider provider;
        REQUIRE(provider.AddArchive(zip_data.data(), zip_data.size()));

        CHECK(provider.HasDir("ndr"));
        CHECK(provider.HasDir("ndr/protocols"));
        CHECK_FALSE(provider.HasDir("other"));
        CHECK_FALSE(provider.HasDir("ndr/main.zeek")); // file, not dir
    }

    TEST_CASE("ReadFile content") {
        std::string content = "event zeek_init() { print \"loaded\"; }";
        auto zip_data = create_test_zip({
            {"scripts/init.zeek", content},
        });
        REQUIRE(! zip_data.empty());

        ZipScriptProvider provider;
        REQUIRE(provider.AddArchive(zip_data.data(), zip_data.size()));

        auto result = provider.ReadFile("scripts/init.zeek");
        REQUIRE(result.has_value());
        CHECK(*result == content);

        // Nonexistent file returns nullopt.
        CHECK_FALSE(provider.ReadFile("scripts/missing.zeek").has_value());
    }

    TEST_CASE("ReadFile empty file") {
        auto zip_data = create_test_zip({
            {"empty.zeek", ""},
        });
        REQUIRE(! zip_data.empty());

        ZipScriptProvider provider;
        REQUIRE(provider.AddArchive(zip_data.data(), zip_data.size()));

        auto result = provider.ReadFile("empty.zeek");
        REQUIRE(result.has_value());
        CHECK(result->empty());
    }

    TEST_CASE("mount root stripping") {
        auto zip_data = create_test_zip({
            {"ndr/main.zeek", "# main"},
            {"ndr/utils.zeek", "# utils"},
        });
        REQUIRE(! zip_data.empty());

        ZipScriptProvider provider;
        REQUIRE(provider.AddArchive(zip_data.data(), zip_data.size(), "C:/zeek/scripts"));

        // Absolute paths with mount root should resolve.
        CHECK(provider.HasFile("C:/zeek/scripts/ndr/main.zeek"));
        CHECK(provider.HasDir("C:/zeek/scripts/ndr"));
        auto result = provider.ReadFile("C:/zeek/scripts/ndr/main.zeek");
        REQUIRE(result.has_value());
        CHECK(*result == "# main");

        // Raw ZIP-relative paths also work (mount root just doesn't strip).
        CHECK(provider.HasFile("ndr/main.zeek"));
    }

    TEST_CASE("mount root boundary — similar prefixes") {
        auto zip_data = create_test_zip({
            {"test.zeek", "# test"},
        });
        REQUIRE(! zip_data.empty());

        ZipScriptProvider provider;
        REQUIRE(provider.AddArchive(zip_data.data(), zip_data.size(), "C:/scripts"));

        // Should match.
        CHECK(provider.HasFile("C:/scripts/test.zeek"));
        // Should NOT match — "C:/scripts2" is not under "C:/scripts/".
        CHECK_FALSE(provider.HasFile("C:/scripts2/test.zeek"));
    }

    TEST_CASE("multiple archives — first wins") {
        auto zip1 = create_test_zip({{"shared.zeek", "archive1"}});
        auto zip2 = create_test_zip({{"shared.zeek", "archive2"}, {"only2.zeek", "only in 2"}});
        REQUIRE(! zip1.empty());
        REQUIRE(! zip2.empty());

        ZipScriptProvider provider;
        REQUIRE(provider.AddArchive(zip1.data(), zip1.size()));
        REQUIRE(provider.AddArchive(zip2.data(), zip2.size()));

        // Duplicate entry: first archive wins.
        auto result = provider.ReadFile("shared.zeek");
        REQUIRE(result.has_value());
        CHECK(*result == "archive1");

        // Entry only in second archive is still found.
        CHECK(provider.HasFile("only2.zeek"));
        auto result2 = provider.ReadFile("only2.zeek");
        REQUIRE(result2.has_value());
        CHECK(*result2 == "only in 2");
    }

    TEST_CASE("package directory with __load__.zeek") {
        auto zip_data = create_test_zip({
            {"pkg/__load__.zeek", "@load ./impl"},
            {"pkg/impl.zeek", "# implementation"},
        });
        REQUIRE(! zip_data.empty());

        ZipScriptProvider provider;
        REQUIRE(provider.AddArchive(zip_data.data(), zip_data.size()));

        CHECK(provider.HasDir("pkg"));
        CHECK(provider.HasFile("pkg/__load__.zeek"));
        auto result = provider.ReadFile("pkg/__load__.zeek");
        REQUIRE(result.has_value());
        CHECK(*result == "@load ./impl");
    }

    TEST_CASE("path normalization in lookups") {
        auto zip_data = create_test_zip({
            {"ndr/main.zeek", "# main"},
        });
        REQUIRE(! zip_data.empty());

        ZipScriptProvider provider;
        REQUIRE(provider.AddArchive(zip_data.data(), zip_data.size()));

        // HasFile/ReadFile normalize internally so callers can pass un-normalized paths.
        CHECK(provider.HasFile("ndr/./main.zeek"));
        CHECK(provider.HasFile("ndr/other/../main.zeek"));
#ifdef _MSC_VER
        CHECK(provider.HasFile("ndr\\main.zeek"));
#endif
    }

    TEST_CASE("singleton lifecycle") {
        // Save and restore any pre-existing instance.
        auto* prev = ZipScriptProvider::GetInstance();

        auto provider = std::make_unique<ZipScriptProvider>();
        auto* raw = provider.get();
        ZipScriptProvider::SetInstance(std::move(provider));
        CHECK(ZipScriptProvider::GetInstance() == raw);

        // Clear.
        ZipScriptProvider::SetInstance(nullptr);
        CHECK(ZipScriptProvider::GetInstance() == nullptr);

        // Restore previous state if there was one.
        if ( prev ) {
            // Can't restore unique_ptr ownership — just leave as null.
            // Tests should not rely on global state anyway.
        }
    }
} // TEST_SUITE
