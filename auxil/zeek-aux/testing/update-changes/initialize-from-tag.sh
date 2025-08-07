# Test update-changes -I when version information is available from git tags.
#
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: test -f CHANGES
# @TEST-EXEC: grep -q '^1.0.0-1' CHANGES
# @TEST-EXEC: grep -q 'Starting CHANGES' CHANGES
# @TEST-EXEC: test $(git rev-list --count HEAD) -eq 2

git init .
echo "Hello" >README
git add README
git commit -m 'init'
git tag v1.0.0

update-changes -I
