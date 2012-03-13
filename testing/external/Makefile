
PUBLIC_REPO=git://git.bro-ids.org/bro-testing
REPOS=`./scripts/find-git-repos `

DIAG=diag.log

all:
	@rm -f $(DIAG)
	@for repo in $(REPOS); do (cd $$repo && make ); done

brief:
	@rm -f $(DIAG)
	@for repo in $(REPOS); do (cd $$repo && make brief ); done

init:
	git clone $(PUBLIC_REPO)

pull:
	@for repo in $(REPOS); do ( cd $$repo && git pull ); done

push:
	@for repo in $(REPOS); do ( cd $$repo && git push origin HEAD ); done

status:
	@for repo in $(REPOS); do ( cd $$repo && echo '>>' $$repo && git status -bs && echo ); done

coverage:
	@for repo in $(REPOS); do (cd $$repo && echo "Coverage for '$$repo' repo:" && make coverage); done

.PHONY: all brief init pull push status coverage
