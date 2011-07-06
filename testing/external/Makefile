
PUBLIC_REPO=git://git.bro-ids.org/bro-testing

DIAG=diag.log

all:
	@rm -f $(DIAG)
	@for repo in *.git; do (cd $$repo && make ); done

brief:
	@rm -f $(DIAG)
	@for repo in *.git; do (cd $$repo && make brief ); done

init:
	git clone $(PUBLIC_REPO) bro-testing.git

pull:
	@for repo in *.git; do ( cd $$repo && git pull ); done
