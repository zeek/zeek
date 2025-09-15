SPHINXOPTS =

NUMJOBS ?= auto

all: html

doc: html

builddir:
	mkdir -p build/html

clean:
	rm -rf build/html

html: builddir
	sphinx-build -j $(NUMJOBS) -b html $(SPHINXOPTS) . ./build/html

livehtml: builddir
	sphinx-autobuild --ignore "*.git/*" --ignore "*.lock" --ignore "*.pyc" --ignore "*.swp" --ignore "*.swpx" --ignore "*.swx" -b html $(SPHINXOPTS) . ./build/html

commit:
	git add * && git commit -m 'Update generated docs'

spicy-%:
	git clone https://github.com/zeek/$@

check-spicy-docs: spicy-tftp
	@echo Refreshing checkouts
	@for REPO in $^; do (cd $$REPO && git pull && git reset HEAD --hard)>/dev/null; done
	@
	@echo Checking whether docs for Spicy integration are up-to-date
	@./devel/spicy/autogen-spicy-docs spicy-tftp
	@
	@git diff --quiet devel/spicy/autogen/ \
		|| (echo "Spicy docs are not up-to-date, rerun './devel/spicy/autogen-spicy-docs'." && exit 1)

.PHONY : all doc builddir clean html livehtml
