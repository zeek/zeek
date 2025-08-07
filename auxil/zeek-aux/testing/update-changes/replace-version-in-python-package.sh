# Verifies that update-changes correctly updates __version__ values as given in
# package-level __init__.py files, when .update-changes.cfg instructs it.
#
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: btest-diff __init__.py

@TEST-START-FILE .update-changes.cfg
function new_version_hook() {
    local version=$1
    replace_version_in_python_package __init__.py $version
}
@TEST-END-FILE

git init

cat >__init__.py <<EOF
__version__ = "1.0",  # with comment
__version__ = "1.0.1-10",  # another comment
__version__ = "2.0.1.dev10",  # Python style
__version__ = "0.0.1.nope"  # should not change
version = "0.0.1"            # should not change
EOF

git add __init__.py
git commit -m 'init'
git tag v1.0.0

update-changes -I

echo "print('Additional change')" >>__init__.py
git add __init__.py
git commit -m 'update'

# Suppress input prompts:
export EDITOR=cat
printf '\n' | update-changes
