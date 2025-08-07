# Verifies that update-changes correctly updates version strings in
# ReST docs, when .update-changes.cfg instructs it.
#
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: btest-diff test.rst

@TEST-START-FILE .update-changes.cfg
function new_version_hook() {
    local version=$1
    replace_version_in_rst test.rst $version
}
@TEST-END-FILE

git init

cat >test.rst <<EOF
.. |version| replace:: 0.1
.. |version| replace:: 0.1-1
.. |version| replace:: 0.1.0
.. |version| replace:: 0.1.0-10
.. |version| replace:: 0.0.1-foo
EOF

git add test.rst
git commit -m 'init'
git tag v1.0.0

update-changes -I

echo ... >>test.rst
git add test.rst
git commit -m 'update'

# Suppress input prompts:
export EDITOR=cat
printf '\n' | update-changes
