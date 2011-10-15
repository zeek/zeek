#!/usr/bin/env python
#
# Derived from docutils standard rst2html.py.
#
# $Id: rst2html.py 4564 2006-05-21 20:44:42Z wiemann $
# Author: David Goodger <goodger@python.org>
# Copyright: This module has been placed in the public domain.
#
#
# Extension: we add to dummy directorives "code" and "console" to be
# compatible with Bro's web site setup.

try:
    import locale
    locale.setlocale(locale.LC_ALL, '')
except:
    pass

import textwrap

from docutils.core import publish_cmdline, default_description

from docutils import nodes
from docutils.parsers.rst import directives, Directive
from docutils.parsers.rst.directives.body import LineBlock

class Literal(Directive):
    #max_line_length = 68
    max_line_length = 0

    required_arguments = 0
    optional_arguments = 1
    final_argument_whitespace = True
    has_content = True

    def wrapped_content(self):
        content = []

        if Literal.max_line_length:
            for line in self.content:
                content += textwrap.wrap(line, Literal.max_line_length, subsequent_indent="      ")
        else:
            content = self.content

        return u'\n'.join(content)

    def run(self):
        self.assert_has_content()
        content = self.wrapped_content()
        literal = nodes.literal_block(content, content)
        return [literal]

directives.register_directive('code', Literal)
directives.register_directive('console', Literal)

description = ('Generates (X)HTML documents from standalone reStructuredText '
               'sources.  ' + default_description)

publish_cmdline(writer_name='html', description=description)



