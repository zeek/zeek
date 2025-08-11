# Test update-changes -r when the repo is cloned from an origin. With commits
# ahead of CHANGES, the release commit should be augmented onto the last.
#
# @TEST-EXEC: bash %INPUT
# @TEST-EXEC: cd clone && git describe --exact-match HEAD | grep -q v1.0.1
# @TEST-EXEC: cd clone && git log --format=%B -n 1 HEAD | grep -q 'This is 1.0.1'
# @TEST-EXEC: cd clone && head -1 CHANGES | grep -q '^1.0.1'
# @TEST-EXEC: cd clone && test $(git rev-list --count HEAD) -eq 4

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

    echo "Meet v1.0.1" >>README
    git add README
    git commit -m "This is 1.0.1"

    # Suppress input prompts:
    export EDITOR=cat
    printf '\n' | update-changes -r
)
