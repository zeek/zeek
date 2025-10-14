import sphinx
import re
from docutils import nodes

# This extension adds a 'literal-emph' directive that operates the same
# as the 'code-block' directive except that it additionally understands
# the **strong emphasis** markup, allowing custom rendering of it to be
# substituted in the final literal block (e.g. HTML adds <strong> elements).
# Adding " (no-emph)" to the end of a line within the 'literal-emph' content
# disables substitutions for that line.

class LiteralEmphNode(nodes.General, nodes.Element):
    pass

class LiteralEmph(sphinx.directives.code.CodeBlock):
    def run(self):
        node = LiteralEmphNode()
        node += super().run()
        return [node]

def visit_litemph_node(self, node):
    pass

def depart_litemph_node(self, node):
    text = self.body[-1]
    text = re.sub(r'\*\*(.*?)\*\*(?!.* \(no-emph\)\n)',
                  r'<strong>\1</strong>',
                  text)
    text = re.sub(r'(.*) \(no-emph\)\n', r'\1\n', text)
    self.body[-1] = text

def setup(app):
    app.add_directive("literal-emph", LiteralEmph)
    app.add_node(LiteralEmphNode,
                 html=(visit_litemph_node, depart_litemph_node))
    return {
        'parallel_read_safe': True,
    }
