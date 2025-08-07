# Test update-changes -R when the repo is cloned from an origin. With commits
# ahead of CHANGES the release commit would be augmented onto the last, but
# this also uses -n to create a new one.
#
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: cd clone && git describe --exact-match HEAD | grep -q v2.0.0
# @TEST-EXEC: cd clone && git log --format=%B -n 1 HEAD | grep -q 'Updating CHANGES and VERSION'
# @TEST-EXEC: cd clone && head -1 CHANGES | grep -q '^2.0.0'
# @TEST-EXEC: cd clone && test $(git rev-list --count HEAD) -eq 5

(
    mkdir origin && cd origin

    git init
    echo "Hello" >README
    git add README
    git commit -m 'init'
    git tag v1.0.0
)

# We need an origin to control update-change's augment-vs-new-commit logic.
git clone origin clone

(
    cd clone

    update-changes -I

    echo ... >>README
    git add README
    git commit -m 'readme update'

    echo "Meet v2.0.0" >>README
    git add README
    git commit -m "This is 2.0.0"

    # Suppress input prompts:
    export EDITOR=cat
    printf '\n' | update-changes -R v2.0.0 -n
)
