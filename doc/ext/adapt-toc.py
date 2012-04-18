
import sys
import re

# Removes the first TOC level, which is just the page title.
def process_html_toc(app, pagename, templatename, context, doctree):

    if not "toc" in context:
        return

    toc = context["toc"]

    lines = toc.strip().split("\n")
    lines = lines[2:-2]

    toc = "\n".join(lines)
    toc = "<ul>" + toc

    context["toc"] = toc

    # print >>sys.stderr, pagename
    # print >>sys.stderr, context["toc"]
    # print >>sys.stderr, "-----"
    # print >>sys.stderr, toc
    # print >>sys.stderr, "===="

def setup(app):
    app.connect('html-page-context', process_html_toc)

