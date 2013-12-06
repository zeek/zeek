"""
Broxygen domain for Sphinx.

Adds directives that allow Sphinx to invoke Bro in order to generate script
reference documentation on the fly.  The directives are:

broxygen:package
    - Shows links to all scripts contained within matching package(s).
broxygen:package_index
    - An index with links to matching package document(s).
broxygen:script
    - Reference for matching script(s) (i.e. everything declared by the script).
broxygen:script_summary
    - Shows link to matching script(s) with it's summary-section comments.
broxygen:script_index
    - An index with links to all matching scrips.
broxygen:proto_analyzer
    - All protocol analyzers and their components (events/bifs, etc.)
broxygen:file_analyzer
    - All file analyzers and their components (events/bifs, etc.)
"""


from sphinx.domains import Domain, ObjType
from sphinx.locale import l_
from docutils.parsers.rst.directives.misc import Include


App = None


def info(msg):
    """Use Sphinx builder to output a console message."""
    global App
    from sphinx.util.console import blue
    App.builder.info(blue(msg))


def pattern_to_filename_component(pattern):
    """Replace certain characters in Broxygen config file target pattern.

    Such that it can be used as part of a (sane) filename.

    """
    return pattern.replace("/", ".").replace("*", "star")


def ensure_dir(path):
    """Should act like ``mkdir -p``."""
    import os
    import errno

    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise


def generate_config(env, type, pattern):
    """Create a Broxygen config file for a particular target.

    It can be used by Bro to generate reST docs for that target.

    """
    import os
    import tempfile
    from sphinx.errors import SphinxError

    work_dir = env.config.broxygen_cache

    if not work_dir:
        raise SphinxError("broxygen_cache not set in sphinx config file")

    ensure_dir(work_dir)
    prefix = "{0}-{1}-".format(type, pattern_to_filename_component(pattern))
    (fd, cfg) = tempfile.mkstemp(suffix=".cfg", prefix=prefix, dir=work_dir)
    generated_file = "{0}.rst".format(cfg)
    config = "{0}\t{1}\t{2}".format(type, pattern, generated_file)
    f = os.fdopen(fd, "w")
    f.write(config)
    f.close()
    return (cfg, generated_file)


def generate_target(env, type, pattern):
    """Create a Broxygen target and build it.

    For a target which hasn't been referenced by any other script, this function
    creates an associated config file then uses Bro w/ it to build the target
    and stores the target information in the build environment.

    If a script references a target that's already found in the build
    environment the results of the previous built are re-used.

    """
    app_data = env.domaindata["broxygen"]

    if (type, pattern) in app_data["targets"]:
        info("Broxygen has cached doc for target '{0} {1}'".format(
            type, pattern))
        return app_data["targets"]

    (cfg, gend_file) = generate_config(env, type, pattern)
    target = BroxygenTarget(type, pattern, cfg, gend_file)
    app_data["targets"][(type, pattern)] = target
    build_target(env, target)
    info("Broxygen built target '{0} {1}'".format(type, pattern))
    return target


def build_target(env, target):
    """Invoke a Bro process to build a Broxygen target."""
    import os
    import subprocess

    path_to_bro = env.config.bro_binary

    if not path_to_bro:
        raise SphinxError("'bro' not set in sphinx config file (path to bro)")

    bro_cmd = "{0} -X {1} broxygen".format(path_to_bro, target.config_file)
    cwd = os.getcwd()
    os.chdir(os.path.dirname(target.config_file))

    try:
        subprocess.check_output(bro_cmd, stderr=subprocess.STDOUT, shell=True)
    except subprocess.CalledProcessError as e:
        from sphinx.errors import SphinxError
        raise SphinxError(
            "Command '{0}' returned non-zero exit status {1}: {2}".format(
                e.cmd, e.returncode, e.output))
    finally:
        os.chdir(cwd)


class BroxygenTarget(object):

    """Some portion of reST documentation that Bro knows how to generate.

    A target is identified by its type and pattern.  E.g. type "script" and
    pattern "broxygen/example.bro".

    """

    def __init__(self, type, pattern, config_file, generated_file):
        self.type = type
        self.pattern = pattern
        self.config_file = config_file
        self.generated_file = generated_file
        self.used_in_docs = set()


class BroxygenDirective(Include):

    """Base class for Broxygen directives.

    It can use Bro to generate reST documentation on the fly and embed it in
    the document at the location of the directive just like the ``.. include::``
    directive.  The only argument is a pattern to identify to Bro which
    pieces of documentation it needs to create.
    """

    required_arguments = 1
    has_content = False

    target_type = None

    def run(self):
        env = self.state.document.settings.env
        info("Broxygen running .. {0}:: {1} in {2}".format(
            self.name, self.arguments[0], env.docname))
        target = generate_target(env, self.target_type, self.arguments[0])
        target.used_in_docs.add(env.docname)
        self.arguments = [target.generated_file]
        return super(BroxygenDirective, self).run()


class PackageDirective(BroxygenDirective):

    target_type = "package"


class PackageIndexDirective(BroxygenDirective):

    target_type = "package_index"


class ScriptDirective(BroxygenDirective):

    target_type = "script"


class ScriptSummaryDirective(BroxygenDirective):

    target_type = "script_summary"


class ScriptIndexDirective(BroxygenDirective):

    target_type = "script_index"


class ProtoAnalyzerDirective(BroxygenDirective):

    target_type = "proto_analyzer"


class FileAnalyzerDirective(BroxygenDirective):

    target_type = "file_analyzer"


class IdentifierDirective(BroxygenDirective):

    target_type = "identifier"


class BroxygenDomain(Domain):

    name = "broxygen"
    label = "Broxygen"

    object_types = {
        "package":          ObjType(l_("package")),
        "package_index":    ObjType(l_("package_index")),
        "script":           ObjType(l_("script")),
        "script_summary":   ObjType(l_("script_summary")),
        "script_index":     ObjType(l_("script_index")),
        "proto_analyzer":   ObjType(l_("proto_analyzer")),
        "file_analyzer":    ObjType(l_("file_analyzer")),
        "identifier":       ObjType(l_("identifier")),
    }

    directives = {
        "package":          PackageDirective,
        "package_index":    PackageIndexDirective,
        "script":           ScriptDirective,
        "script_summary":   ScriptSummaryDirective,
        "script_index":     ScriptIndexDirective,
        "proto_analyzer":   ProtoAnalyzerDirective,
        "file_analyzer":    FileAnalyzerDirective,
        "identifier":       IdentifierDirective,
    }

    roles = {}

    initial_data = {
        "targets": {}
    }

    def clear_doc(self, docname):
        """Update Broxygen targets referenced in docname.

        If it's the last place the target was referenced, remove it from
        the build environment and delete any generated config/reST files
        associated with it from the cache.

        """
        import os

        stale_targets = []

        for (type, pattern), target in self.data["targets"].items():
            if docname in target.used_in_docs:
                target.used_in_docs.remove(docname)

                if not target.used_in_docs:
                    stale_targets.append(target)

        for target in stale_targets:
            del self.data["targets"][(target.type, target.pattern)]
            os.remove(target.config_file)
            os.remove(target.generated_file)

    def get_objects(self):
        """No Broxygen-generated content is itself linkable/searchable."""
        return []


def env_get_outdated_hook(app, env, added, changed, removed):
    """Check whether to re-read any documents referencing Broxygen targets.

    To do that we have to ask Bro to rebuild each target and compare the
    before and after modification times of the generated reST output file.
    If Bro changed it, then the document containing the Broxygen directive
    needs to be re-read.

    """
    import os

    reread = set()

    for target in app.env.domaindata["broxygen"]["targets"].values():
        before_mtime = os.stat(target.generated_file)
        build_target(env, target)
        after_mtime = os.stat(target.generated_file)

        if after_mtime > before_mtime:
            info("Broxygen target '{0} {1}' outdated".format(
                target.type, target.pattern))

            for docname in target.used_in_docs:
                if docname not in removed:
                    info("  in document: {0}".format(docname))
                    reread.add(docname)

    return list(reread)


def setup(app):
    global App
    App = app
    app.add_domain(BroxygenDomain)
    app.add_config_value("bro_binary", None, "env")
    app.add_config_value("broxygen_cache", None, "env")
    app.connect("env-get-outdated", env_get_outdated_hook)
