
all:
	test -d html || mkdir html
	for i in *.rst; do echo "$$i ..."; ./bin/rst2html.py $$i >html/`echo $$i | sed 's/rst$$/html/g'`; done

clean:
	rm -rf html
