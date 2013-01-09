import os
from sphinx.directives.code import LiteralInclude

def setup(app):
    app.add_directive('rootedliteralinclude', RootedLiteralInclude)

class RootedLiteralInclude(LiteralInclude):
    """
    Like ``.. literalinclude::``, but the argument is an absolute path
    which may contain environment variables which will be expanded when
    generating documents.
    """

    def run(self):
        document = self.state.document
        if not document.settings.file_insertion_enabled:
            return [document.reporter.warning('File insertion disabled',
                                              line=self.lineno)]
        env = document.settings.env

        expanded_arg = os.path.expandvars(self.arguments[0])
        sphinx_src_relation = os.path.relpath(expanded_arg, env.srcdir)
        self.arguments[0] = os.path.join(os.sep, sphinx_src_relation)

        return super(RootedLiteralInclude, self).run()
