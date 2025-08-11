# Verifies that update-changes correctly updates version strings in C header
# files, when .update-changes.cfg instructs it.
#
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: btest-diff header.h

@TEST-START-FILE .update-changes.cfg
function new_version_hook() {
    local version=$1
    replace_version_in_c_header header.h $version
}
@TEST-END-FILE

git init

cat >header.h <<EOF
#define   ZEEK_VERSION "1.0" /* with comment */
#define   ZEEK_VERSION "1.0-1" /* with comment */
  #define FOO_VERSION  "1.0.1-10" // another comment
EOF

git add header.h
git commit -m 'init'
git tag v1.0.0

update-changes -I

echo ... >>header.h
git add header.h
git commit -m 'update'

# Suppress input prompts:
export EDITOR=cat
printf '\n' | update-changes
