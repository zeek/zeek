def setup(app):
    pass

# -*- coding: utf-8 -*-
"""

Modified version of the the Pygments reStructuredText directive. -Robin

This provides two new directives:

    - .. code:: [<format>]

      Highlights the following code block according to <format> if
      given (e.g., "c", "python", etc.).

    - .. console::

      Highlits the following code block as a shell session.

    For compatibility with the original version, "sourcecode" is
    equivalent to "code".

Original comment:

    The Pygments reStructuredText directive
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    This fragment is a Docutils_ 0.5 directive that renders source code
    (to HTML only, currently) via Pygments.

    To use it, adjust the options below and copy the code into a module
    that you import on initialization.  The code then automatically
    registers a ``sourcecode`` directive that you can use instead of
    normal code blocks like this::

        .. sourcecode:: python

            My code goes here.

    If you want to have different code styles, e.g. one with line numbers
    and one without, add formatters with their names in the VARIANTS dict
    below.  You can invoke them instead of the DEFAULT one by using a
    directive option::

        .. sourcecode:: python
            :linenos:

            My code goes here.

    Look at the `directive documentation`_ to get all the gory details.

    .. _Docutils: http://docutils.sf.net/
    .. _directive documentation:
       http://docutils.sourceforge.net/docs/howto/rst-directives.html

    :copyright: Copyright 2006-2010 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

# Options
# ~~~~~~~

# Set to True if you want inline CSS styles instead of classes
INLINESTYLES = False

from pygments.formatters import HtmlFormatter

class MyHtmlFormatter(HtmlFormatter):
    def format_unencoded(self, tokensource, outfile):

        # A NOP currently.
        new_tokens = []
        for (i, piece) in tokensource:
            new_tokens += [(i, piece)]

        return super(MyHtmlFormatter, self).format_unencoded(new_tokens, outfile)

# The default formatter
DEFAULT = MyHtmlFormatter(noclasses=INLINESTYLES, cssclass="pygments")

# Add name -> formatter pairs for every variant you want to use
VARIANTS = {
    # 'linenos': HtmlFormatter(noclasses=INLINESTYLES, linenos=True),
}


import textwrap

from docutils import nodes
from docutils.parsers.rst import directives, Directive

from pygments import highlight
from pygments.lexers import get_lexer_by_name, guess_lexer, TextLexer
from pygments.token import Text, Keyword, Error, Operator, Name
from pygments.filter import Filter

# Ugly hack to register the Bro lexer. I'm sure there's a better way to do it,
# but it's not obvious ...
from bro_lexer.bro import BroLexer
from pygments.lexers._mapping import LEXERS
LEXERS['BroLexer'] = ('bro_lexer.bro', BroLexer.name, BroLexer.aliases, BroLexer.filenames, ())

class Pygments(Directive):
    """ Source code syntax hightlighting.
    """
    #max_line_length = 68
    max_line_length = 0

    required_arguments = 0
    optional_arguments = 1
    final_argument_whitespace = True
    option_spec = dict([(key, directives.flag) for key in VARIANTS])
    has_content = True

    def wrapped_content(self):
        content = []

        if Console.max_line_length:
            for line in self.content:
                content += textwrap.wrap(line, Console.max_line_length, subsequent_indent="      ")
        else:
            content = self.content

        return u'\n'.join(content)

    def run(self):
        self.assert_has_content()

        content = self.wrapped_content()

        if len(self.arguments) > 0:
            try:
                lexer = get_lexer_by_name(self.arguments[0])
            except (ValueError, IndexError):
                # lexer not found, use default.
                lexer = TextLexer()
        else:
            lexer = guess_lexer(content)

        # import sys
        # print >>sys.stderr, self.arguments, lexer.__class__

        # take an arbitrary option if more than one is given
        formatter = self.options and VARIANTS[self.options.keys()[0]] or DEFAULT
        parsed = highlight(content, lexer, formatter)
        return [nodes.raw('', parsed, format='html')]

class MyFilter(Filter):
    def filter(self, lexer, stream):

        bol = True

        for (ttype, value) in stream:
            # Color the '>' prompt sign.
            if bol and ttype is Text and value == ">":
                ttype = Name.Variable.Class # This gives us a nice red.

            # Discolor builtin, that can look funny.
            if ttype is Name.Builtin:
                ttype = Text

            bol = value.endswith("\n")

            yield (ttype, value)

class Console(Pygments):
    required_arguments = 0
    optional_arguments = 0

    def run(self):
        self.assert_has_content()
        content = self.wrapped_content()
        lexer = get_lexer_by_name("sh")
        lexer.add_filter(MyFilter())
        parsed = highlight(content, lexer, DEFAULT)
        return [nodes.raw('', parsed, format='html')]

directives.register_directive('sourcecode', Pygments)
directives.register_directive('code', Pygments)
directives.register_directive('console', Console)
