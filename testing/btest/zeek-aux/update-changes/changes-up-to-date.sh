# Test update-changes -c. On an absent repo, this should fail. When there have
# not been commits since the last CHANGES update, it should succeed, and after
# subsequent commits it should fail again.
#
# @TEST-EXEC-FAIL: update-changes -c
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: update-changes -c
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC-FAIL: update-changes -c

if [ ! -d .git ]; then
    git init .
    echo "Hello" >README
    git add README
    git commit -m 'init'

    echo "1.0.0" | update-changes -I
else
    echo >>README
    git add README
    git commit -m 'readme update'
fi
