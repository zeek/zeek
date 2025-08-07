# Test update-changes -I when version information is in the VERSION file, which
# update-changes wants confirmation for.
#
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: test -f CHANGES
# @TEST-EXEC: grep -q '^1.0.0' CHANGES
# @TEST-EXEC: grep -q 'Starting CHANGES' CHANGES
# @TEST-EXEC: test $(git rev-list --count HEAD) -eq 2

git init .
echo "1.0.0" >VERSION
git add VERSION
git commit -m 'init'

echo y | update-changes -I
