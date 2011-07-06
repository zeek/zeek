
PUBLIC_REPO=git://git.bro-ids.org/bro-testing

all:
	@for repo in *.git; do (echo "==== $$repo" && cd $$repo && btest ); echo; done

init:
	git clone $(PUBLIC_REPO) bro-testing.git

pull:
	@for repo in *.git; do ( cd $$repo && git pull ); done
