zeek_add_subdir_library(
    zeekygen
    SOURCES
    Manager.cc
    Info.h
    PackageInfo.cc
    ScriptInfo.cc
    IdentifierInfo.cc
    Target.cc
    Configuration.cc
    ReStructuredTextTable.cc
    utils.cc)

# Treat BIFs as builtin (alternative mode).
bif_target(zeekygen.bif)
