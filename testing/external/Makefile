
PUBLIC_REPO=/home/robin/tmp/bro-tests

all:
	@for repo in *.git; do ( cd $$repo && btest ); done

init:
	git clone $(PUBLIC_REPO) public.git

pull:
	@for repo in *.git; do ( cd $$repo && git pull ); done
