# Test update-changes -I when no version information is present, and the user is
# prompted to provide one.
#
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: test -f CHANGES
# @TEST-EXEC: grep -q '^1.0.0' CHANGES
# @TEST-EXEC: grep -q 'Starting CHANGES' CHANGES
# @TEST-EXEC: test $(git rev-list --count HEAD) -eq 2

git init .
echo "Hello" >README
git add README
git commit -m 'init'

echo "1.0.0" | update-changes -I
