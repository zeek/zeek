
all: html

doc: html

builddir:
	mkdir -p build/html

clean:
	rm -rf build/html

html: builddir
	sphinx-build -b html . ./build/html

livehtml: builddir
	sphinx-autobuild --ignore "*.git/*" --ignore "*.lock" --ignore "*.pyc" --ignore "*.swp" --ignore "*.swpx" --ignore "*.swx" -b html . ./build/html

.PHONY : all doc builddir clean html livehtml
