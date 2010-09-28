EXTRA_DIST = README.txt
SUBDIRS = ref-manual quick-start user-manual

doc:
	@echo "Build Bro Documentation (html and pdf)"
	for d in $(SUBDIRS); do \
		( cd $$d && $(MAKE) $@ ); \
	done

