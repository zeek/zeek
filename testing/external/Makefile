
PUBLIC_REPO=https://github.com/zeek/zeek-testing
REPOS=`./scripts/find-git-repos`

DIAG=diag.log

all:
	@rm -f $(DIAG)
	@for repo in $(REPOS); do (cd $$repo && make -s ); done

brief:
	@rm -f $(DIAG)
	@for repo in $(REPOS); do (cd $$repo && make -s brief ); done

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

update-timing:
	@for repo in $(REPOS); do (cd $$repo && echo "Coverage for '$$repo' repo:" && make update-timing); done

.PHONY: all brief init pull push status coverage
