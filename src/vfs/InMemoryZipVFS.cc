// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/vfs/InMemoryZipVFS.h"

#include <zip.h>
#include <algorithm>
#include <filesystem>

namespace zeek::vfs {

InMemoryZipVFS::InMemoryZipVFS() = default;

InMemoryZipVFS::~InMemoryZipVFS() {
    for ( auto& archive : archives_ ) {
        if ( archive.handle )
            zip_close(archive.handle);
    }
}

bool InMemoryZipVFS::AddArchive(const void* data, size_t size, const std::string& mount_root) {
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
    archives_.push_back(std::move(archive));
    return true;
}

std::string InMemoryZipVFS::NormalizePath(const std::string& path) {
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

std::string InMemoryZipVFS::StripMountRoot(const std::string& normalized, const Archive& archive) {
    if ( ! archive.mount_root.empty() && normalized.size() > archive.mount_root.size() &&
         normalized.compare(0, archive.mount_root.size(), archive.mount_root) == 0 )
        return normalized.substr(archive.mount_root.size());
    return normalized;
}

bool InMemoryZipVFS::HasFile(const std::string& path) const {
    std::string normalized = NormalizePath(path);

    for ( const auto& archive : archives_ ) {
        std::string zip_path = StripMountRoot(normalized, archive);
        if ( zip_name_locate(archive.handle, zip_path.c_str(), 0) >= 0 )
            return true;
    }
    return false;
}

bool InMemoryZipVFS::HasDir(const std::string& path) const {
    std::string normalized = NormalizePath(path);

    for ( const auto& archive : archives_ ) {
        std::string zip_path = StripMountRoot(normalized, archive);

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

std::optional<VFSResult> InMemoryZipVFS::ReadFile(const std::string& path) const {
    std::string normalized = NormalizePath(path);

    for ( const auto& archive : archives_ ) {
        std::string zip_path = StripMountRoot(normalized, archive);

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

        // Build a stable identifier for deduplication: "zip://<normalized-path>"
        std::string identifier = "zip://" + normalized;
        return VFSResult{std::move(content), std::move(identifier)};
    }

    return std::nullopt;
}

} // namespace zeek::vfs

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

TEST_SUITE("InMemoryZipVFS") {
    using zeek::vfs::InMemoryZipVFS;

    TEST_CASE("NormalizePath basics") {
        // Forward slashes unchanged.
        CHECK(InMemoryZipVFS::NormalizePath("foo/bar") == "foo/bar");
        CHECK(InMemoryZipVFS::NormalizePath("ndr/main.zeek") == "ndr/main.zeek");

        // Backslash conversion.
        CHECK(InMemoryZipVFS::NormalizePath("foo\\bar") == "foo/bar");
        CHECK(InMemoryZipVFS::NormalizePath("foo\\bar\\baz.zeek") == "foo/bar/baz.zeek");

        // Collapse . and ..
        CHECK(InMemoryZipVFS::NormalizePath("foo/./bar") == "foo/bar");
        CHECK(InMemoryZipVFS::NormalizePath("foo/baz/../bar") == "foo/bar");

        // Strip leading ./
        CHECK(InMemoryZipVFS::NormalizePath("./foo/bar") == "foo/bar");
        CHECK(InMemoryZipVFS::NormalizePath("./foo") == "foo");

        // Strip trailing /
        CHECK(InMemoryZipVFS::NormalizePath("foo/bar/") == "foo/bar");

        // Empty and root.
        CHECK(InMemoryZipVFS::NormalizePath("") == "");
        CHECK(InMemoryZipVFS::NormalizePath(".") == ".");

#ifdef _MSC_VER
        // Windows absolute path.
        CHECK(InMemoryZipVFS::NormalizePath("C:\\scripts\\ndr\\main.zeek") == "C:/scripts/ndr/main.zeek");
        CHECK(InMemoryZipVFS::NormalizePath("C:\\scripts\\ndr\\..\\main.zeek") == "C:/scripts/main.zeek");
#endif
    }

    TEST_CASE("AddArchive with valid ZIP") {
        auto zip_data = create_test_zip({
            {"test/hello.zeek", "print \"hello\";"},
            {"test/world.zeek", "print \"world\";"},
        });
        REQUIRE(! zip_data.empty());

        InMemoryZipVFS vfs;
        CHECK(vfs.AddArchive(zip_data.data(), zip_data.size()));
    }

    TEST_CASE("AddArchive with invalid data") {
        InMemoryZipVFS vfs;
        const char* garbage = "this is not a zip file";
        CHECK_FALSE(vfs.AddArchive(garbage, strlen(garbage)));
    }

    TEST_CASE("AddArchive with empty buffer") {
        InMemoryZipVFS vfs;
        // libzip accepts a zero-size buffer as a valid empty archive.
        uint8_t empty = 0;
        CHECK(vfs.AddArchive(&empty, 0));
        // But it has no files.
        CHECK_FALSE(vfs.HasFile("anything.zeek"));
    }

    TEST_CASE("HasFile") {
        auto zip_data = create_test_zip({
            {"ndr/main.zeek", "# main script"},
            {"ndr/protocols/http.zeek", "# http"},
        });
        REQUIRE(! zip_data.empty());

        InMemoryZipVFS vfs;
        REQUIRE(vfs.AddArchive(zip_data.data(), zip_data.size()));

        CHECK(vfs.HasFile("ndr/main.zeek"));
        CHECK(vfs.HasFile("ndr/protocols/http.zeek"));
        CHECK_FALSE(vfs.HasFile("ndr/nonexistent.zeek"));
        CHECK_FALSE(vfs.HasFile("other/file.zeek"));

        // Directories are not files.
        CHECK_FALSE(vfs.HasFile("ndr"));
        CHECK_FALSE(vfs.HasFile("ndr/"));
    }

    TEST_CASE("HasDir with implicit directories") {
        // ZIP has NO explicit directory entries — only files. HasDir must infer.
        auto zip_data = create_test_zip({
            {"ndr/main.zeek", "# main"},
            {"ndr/protocols/http.zeek", "# http"},
        });
        REQUIRE(! zip_data.empty());

        InMemoryZipVFS vfs;
        REQUIRE(vfs.AddArchive(zip_data.data(), zip_data.size()));

        CHECK(vfs.HasDir("ndr"));
        CHECK(vfs.HasDir("ndr/protocols"));
        CHECK_FALSE(vfs.HasDir("other"));
        CHECK_FALSE(vfs.HasDir("ndr/main.zeek")); // file, not dir
    }

    TEST_CASE("ReadFile content") {
        std::string content = "event zeek_init() { print \"loaded\"; }";
        auto zip_data = create_test_zip({
            {"scripts/init.zeek", content},
        });
        REQUIRE(! zip_data.empty());

        InMemoryZipVFS vfs;
        REQUIRE(vfs.AddArchive(zip_data.data(), zip_data.size()));

        auto result = vfs.ReadFile("scripts/init.zeek");
        REQUIRE(result.has_value());
        CHECK(result->content == content);
        CHECK(result->identifier == "zip://scripts/init.zeek");

        // Nonexistent file returns nullopt.
        CHECK_FALSE(vfs.ReadFile("scripts/missing.zeek").has_value());
    }

    TEST_CASE("ReadFile empty file") {
        auto zip_data = create_test_zip({
            {"empty.zeek", ""},
        });
        REQUIRE(! zip_data.empty());

        InMemoryZipVFS vfs;
        REQUIRE(vfs.AddArchive(zip_data.data(), zip_data.size()));

        auto result = vfs.ReadFile("empty.zeek");
        REQUIRE(result.has_value());
        CHECK(result->content.empty());
    }

    TEST_CASE("mount root stripping") {
        auto zip_data = create_test_zip({
            {"ndr/main.zeek", "# main"},
            {"ndr/utils.zeek", "# utils"},
        });
        REQUIRE(! zip_data.empty());

        InMemoryZipVFS vfs;
        REQUIRE(vfs.AddArchive(zip_data.data(), zip_data.size(), "C:/zeek/scripts"));

        // Absolute paths with mount root should resolve.
        CHECK(vfs.HasFile("C:/zeek/scripts/ndr/main.zeek"));
        CHECK(vfs.HasDir("C:/zeek/scripts/ndr"));
        auto result = vfs.ReadFile("C:/zeek/scripts/ndr/main.zeek");
        REQUIRE(result.has_value());
        CHECK(result->content == "# main");

        // Raw ZIP-relative paths also work (mount root just doesn't strip).
        CHECK(vfs.HasFile("ndr/main.zeek"));
    }

    TEST_CASE("mount root boundary — similar prefixes") {
        auto zip_data = create_test_zip({
            {"test.zeek", "# test"},
        });
        REQUIRE(! zip_data.empty());

        InMemoryZipVFS vfs;
        REQUIRE(vfs.AddArchive(zip_data.data(), zip_data.size(), "C:/scripts"));

        // Should match.
        CHECK(vfs.HasFile("C:/scripts/test.zeek"));
        // Should NOT match — "C:/scripts2" is not under "C:/scripts/".
        CHECK_FALSE(vfs.HasFile("C:/scripts2/test.zeek"));
    }

    TEST_CASE("multiple archives — first wins") {
        auto zip1 = create_test_zip({{"shared.zeek", "archive1"}});
        auto zip2 = create_test_zip({{"shared.zeek", "archive2"}, {"only2.zeek", "only in 2"}});
        REQUIRE(! zip1.empty());
        REQUIRE(! zip2.empty());

        InMemoryZipVFS vfs;
        REQUIRE(vfs.AddArchive(zip1.data(), zip1.size()));
        REQUIRE(vfs.AddArchive(zip2.data(), zip2.size()));

        // Duplicate entry: first archive wins.
        auto result = vfs.ReadFile("shared.zeek");
        REQUIRE(result.has_value());
        CHECK(result->content == "archive1");

        // Entry only in second archive is still found.
        CHECK(vfs.HasFile("only2.zeek"));
        auto result2 = vfs.ReadFile("only2.zeek");
        REQUIRE(result2.has_value());
        CHECK(result2->content == "only in 2");
    }

    TEST_CASE("package directory with __load__.zeek") {
        auto zip_data = create_test_zip({
            {"pkg/__load__.zeek", "@load ./impl"},
            {"pkg/impl.zeek", "# implementation"},
        });
        REQUIRE(! zip_data.empty());

        InMemoryZipVFS vfs;
        REQUIRE(vfs.AddArchive(zip_data.data(), zip_data.size()));

        CHECK(vfs.HasDir("pkg"));
        CHECK(vfs.HasFile("pkg/__load__.zeek"));
        auto result = vfs.ReadFile("pkg/__load__.zeek");
        REQUIRE(result.has_value());
        CHECK(result->content == "@load ./impl");
    }

    TEST_CASE("path normalization in lookups") {
        auto zip_data = create_test_zip({
            {"ndr/main.zeek", "# main"},
        });
        REQUIRE(! zip_data.empty());

        InMemoryZipVFS vfs;
        REQUIRE(vfs.AddArchive(zip_data.data(), zip_data.size()));

        // HasFile/ReadFile normalize internally so callers can pass un-normalized paths.
        CHECK(vfs.HasFile("ndr/./main.zeek"));
        CHECK(vfs.HasFile("ndr/other/../main.zeek"));
#ifdef _MSC_VER
        CHECK(vfs.HasFile("ndr\\main.zeek"));
#endif
    }
} // TEST_SUITE
