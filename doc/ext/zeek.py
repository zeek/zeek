"""
The Zeek domain for Sphinx.
"""

import collections


def setup(Sphinx):
    Sphinx.add_domain(ZeekDomain)
    Sphinx.add_node(see)
    Sphinx.add_directive_to_domain("zeek", "see", SeeDirective)
    Sphinx.connect("object-description-transform", object_description_transform)
    Sphinx.connect("doctree-resolved", process_see_nodes)
    return {
        "parallel_read_safe": True,
    }


from sphinx import addnodes, version_info
from sphinx.directives import ObjectDescription
from sphinx.domains import Domain, Index, ObjType
from sphinx.locale import _
from sphinx.roles import XRefRole
from sphinx.util import docfields, logging
from sphinx.util.nodes import make_refnode

logger = logging.getLogger(__name__)

from docutils import nodes
from docutils.parsers.rst import Directive, directives


class see(nodes.General, nodes.Element):
    refs = []


class SeeDirective(Directive):
    has_content = True

    def run(self):
        n = see("")
        n.refs = " ".join(self.content).split()
        return [n]


# Wrapper for creating a tuple for index nodes, staying backwards
# compatible to Sphinx < 1.4:
def make_index_tuple(indextype, indexentry, targetname, targetname2):
    if version_info >= (1, 4, 0, "", 0):
        return (indextype, indexentry, targetname, targetname2, None)
    else:
        return (indextype, indexentry, targetname, targetname2)


def object_description_transform(app, domain, objtype, contentnode):
    """
    Add all collected record fields as a "Field" field to a ZeekType.
    """
    if domain != "zeek" or objtype != "type":
        return

    type_name = app.env.ref_context["zeek:type"]
    record_fields = app.env.domaindata["zeek"].get("fields", {}).get(type_name)

    if not record_fields:
        return

    field_list = contentnode[0]

    name = nodes.field_name("", _("Fields"))
    body = nodes.field_body("")

    for field_name, record_field in record_fields.items():
        body += record_field["idx"]
        body += record_field["signode"]

    field_list.append(nodes.field("", name, body))


def process_see_nodes(app, doctree, fromdocname):
    for node in doctree.traverse(see):
        content = []
        para = nodes.paragraph()
        para += nodes.Text("See also:", "See also:")
        for name in node.refs:
            join_str = " "
            if name != node.refs[0]:
                join_str = ", "
            link_txt = join_str + name
            if name not in app.env.domaindata["zeek"]["idtypes"]:
                # Just create the text and issue warning
                logger.warning(
                    '%s: unknown target for ".. zeek:see:: %s"',
                    fromdocname,
                    name,
                    location=node,
                )
                para += nodes.Text(link_txt, link_txt)
            else:
                # Create a reference
                typ = app.env.domaindata["zeek"]["idtypes"][name]
                todocname = app.env.domaindata["zeek"]["objects"][(typ, name)]

                newnode = nodes.reference("", "")
                innernode = nodes.literal(_(name), _(name), classes=["xref"])
                newnode["refdocname"] = todocname
                newnode["refuri"] = app.builder.get_relative_uri(fromdocname, todocname)
                newnode["refuri"] += "#" + typ + "-" + name
                newnode.append(innernode)
                para += nodes.Text(join_str, join_str)
                para += newnode

        content.append(para)
        node.replace_self(content)


class ZeekGeneric(ObjectDescription):
    option_spec = {"source-code": directives.unchanged}

    def __init__(self, *args, **kwargs):
        super(ObjectDescription, self).__init__(*args, **kwargs)
        options = args[2]
        self.code_url = None

        if "source-code" in options and "zeek-code-url" in self.env.config:
            base_url = self.env.config["zeek-code-url"]
            path, start, end = options["source-code"].split()
            path_parts = path.split("/")
            file_name = path_parts[-1]

            # Don't have anything to link to for BIFs
            if not file_name.endswith(".bif.zeek"):
                self.code_url = f"{base_url}/scripts/{path}#L{start}-L{end}"

    def get_obj_name(self):
        return self.objtype

    def update_type_map(self, idname):
        if "idtypes" not in self.env.domaindata["zeek"]:
            self.env.domaindata["zeek"]["idtypes"] = {}
        self.env.domaindata["zeek"]["idtypes"][idname] = self.get_obj_name()

    def process_signode(self, name, sig, signode, targetname):
        signode["names"].append(targetname)
        signode["ids"].append(targetname)
        signode["first"] = not self.names
        self.state.document.note_explicit_target(signode)

    def add_target_and_index(self, name, sig, signode):
        targetname = self.get_obj_name() + "-" + name

        if targetname not in self.state.document.ids:
            self.process_signode(name, sig, signode, targetname)

            objects = self.env.domaindata["zeek"]["objects"]
            key = (self.get_obj_name(), name)

            if (
                key in objects
                and self.get_obj_name() != "id"
                and self.get_obj_name() != "type"
                and self.get_obj_name() != "field"
            ):
                logger.warning(
                    "%s: duplicate description of %s %s, other instance in %s %s",
                    self.env.docname,
                    self.get_obj_name(),
                    name,
                    self.env.doc2path(objects[key]),
                    self.lineno,
                )

            objects[key] = self.env.docname
            self.update_type_map(name)

        indextext = self.get_index_text(name)

        if indextext:
            self.indexnode["entries"].append(
                make_index_tuple("single", indextext, targetname, targetname)
            )

    def get_index_text(self, name):
        return _("%s (%s)") % (name, self.get_obj_name())

    def handle_signature(self, sig, signode):
        if self.code_url:
            signode += nodes.reference(
                sig, sig, refuri=self.code_url, reftitle="View Source Code"
            )

            # Could embed snippets directly, but would probably want to clean
            # up how it's done: don't use an external script, figure out why
            # tab/indentation is broken, toggle snippet visibility on mouse
            # hover or other explicit button/link, fix the colors/theming...
            # But for now, leaving this commented out as an example and quick
            # way of checking that the code ranges that Zeekygen outputs are
            # sensible.

            # import urllib
            # snippet_target = urllib.parse.quote(self.code_url, '')
            # snippet_url = 'https://emgithub.com/embed.js'
            # snippet_url += f'?target={snippet_target}'
            # snippet_url += '&style=github'
            # snippet_url += '&showLineNumbers=on'
            # snippet_url += '&showBorder=on'
            # snippet_url += '&ts=4'
            # rawnode = nodes.raw('', f'<script src="{snippet_url}"></script>',
            #                     format='html')
            # signode += rawnode

        else:
            signode += addnodes.desc_name("", sig)

        return sig


class ZeekNamespace(ZeekGeneric):
    def add_target_and_index(self, name, sig, signode):
        targetname = self.get_obj_name() + "-" + name

        if targetname not in self.state.document.ids:
            signode["names"].append(targetname)
            signode["ids"].append(targetname)
            signode["first"] = not self.names
            self.state.document.note_explicit_target(signode)

            objects = self.env.domaindata["zeek"]["objects"]
            key = (self.get_obj_name(), name)
            objects[key] = self.env.docname
            self.update_type_map(name)

        indextext = self.get_index_text(name)
        self.indexnode["entries"].append(
            make_index_tuple("single", indextext, targetname, targetname)
        )
        self.indexnode["entries"].append(
            make_index_tuple("single", f"namespaces; {sig}", targetname, targetname)
        )

    def get_index_text(self, name):
        return _("%s (namespace); %s") % (name, self.env.docname)

    def handle_signature(self, sig, signode):
        signode += addnodes.desc_name("", sig)
        return sig


class ZeekEnum(ZeekGeneric):
    def add_target_and_index(self, name, sig, signode):
        targetname = self.get_obj_name() + "-" + name

        if targetname not in self.state.document.ids:
            self.process_signode(name, sig, signode, targetname)

            objects = self.env.domaindata["zeek"]["objects"]
            key = (self.get_obj_name(), name)
            objects[key] = self.env.docname
            self.update_type_map(name)

        # indextext = self.get_index_text(name)
        # self.indexnode['entries'].append(make_index_tuple('single', indextext,
        #                                  targetname, targetname))
        m = sig.split()

        if len(m) < 2:
            logger.warning(
                "%s: zeek:enum directive missing argument(s)", self.env.docname
            )
            return

        if m[1] == "Notice::Type":
            if "notices" not in self.env.domaindata["zeek"]:
                self.env.domaindata["zeek"]["notices"] = []
            self.env.domaindata["zeek"]["notices"].append(
                (m[0], self.env.docname, targetname)
            )

        self.indexnode["entries"].append(
            make_index_tuple(
                "single", f"{m[1]} (enum values); {m[0]}", targetname, targetname
            )
        )

    def handle_signature(self, sig, signode):
        m = sig.split()
        name = m[0]
        signode += addnodes.desc_name("", name)
        return name


class ZeekParamField(docfields.GroupedField):
    has_arg = True
    is_typed = True


class ZeekIdentifier(ZeekGeneric):
    zeek_param_field = ZeekParamField("param", label="Parameters", can_collapse=True)
    field_type_map = {"param": (zeek_param_field, False)}

    def get_index_text(self, name):
        return name

    def get_field_type_map(self):
        return self.field_type_map


class ZeekNative(ZeekGeneric):
    def handle_signature(self, sig, signode):
        # The run() method is overridden to drop signode anyway in favor of
        # simply adding the index and a target nodes and leaving up
        # to the .rst document to explicitly add things that need to
        # be presented in the final rendering (e.g. a section header)
        self.native_name = sig
        return sig

    def process_signode(self, name, sig, signode, targetname):
        pass

    def run(self):
        ns = super().run()
        index_node = ns[0]

        target_id = self.get_obj_name() + "-" + self.native_name
        target_node = nodes.target("", "", ids=[target_id])
        self.state.document.note_explicit_target(target_node)

        # Replace the description node from Sphinx with a simple target node
        return [index_node, target_node]


class ZeekKeyword(ZeekNative):
    def get_index_text(self, name):
        if name and name[0] == "@":
            return _("%s (directive)") % (name)
        else:
            return _("%s (keyword)") % (name)


class ZeekAttribute(ZeekNative):
    def get_index_text(self, name):
        return _("%s (attribute)") % (name)


class ZeekType(ZeekGeneric):
    """
    Put the type that's currently documented into env.ref_context
    for usage with the ZeekField directive.
    """

    def before_content(self):
        self.env.ref_context["zeek:type"] = self.arguments[0]

    def after_content(self):
        self.env.ref_context.pop("zeek:type", None)


class ZeekField(ZeekGeneric):
    def handle_signature(self, sig, signode):
        """
        The signature for .. zeek:field: currently looks like the following:

          .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`
        """
        parts = sig.split(" ", 2)
        name, type_str = parts[0:2]
        record_type = self.env.ref_context["zeek:type"]
        fullname = "$".join([record_type, name])
        attrs_str = ""
        if len(parts) == 3:
            attrs_str = parts[2]

        type_nodes, _ = self.state.inline_text(type_str, -1)

        signode += addnodes.desc_name(name, name)
        signode += addnodes.desc_sig_punctuation("", ":")
        signode += addnodes.desc_sig_space()
        signode += type_nodes

        if attrs_str:
            attr_nodes, _ = self.state.inline_text(attrs_str, -1)
            signode += addnodes.desc_sig_space()
            signode += attr_nodes

        signode["class"] = record_type
        signode["fullname"] = fullname

        return fullname

    def run(self):
        idx, signode = super().run()

        record_type = self.env.ref_context["zeek:type"]

        fields = self.env.domaindata["zeek"].setdefault("fields", {})
        rfields = fields.setdefault(record_type, collections.OrderedDict())
        rfields[signode[0]["fullname"]] = {
            "idx": idx,
            "signode": signode,
        }

        return []


class ZeekNativeType(ZeekNative):
    def get_obj_name(self):
        # As opposed to using 'native-type', just imitate 'type'.
        return "type"


class ZeekFieldXRefRole(XRefRole):
    def process_link(self, env, refnode, has_explicit_title, title, target):
        title, target = super().process_link(
            env, refnode, has_explicit_title, title, target
        )

        parts = title.split("$")
        if len(parts) == 2 and parts[0] and parts[1]:
            # If a field is in Type$field, form, strip Type.
            title = parts[1]

        return title, target


class ZeekNotices(Index):
    """
    Index subclass to provide the Zeek notices index.
    """

    name = "noticeindex"
    localname = _("Zeek Notice Index")
    shortname = _("notices")

    def generate(self, docnames=None):
        content = {}

        if "notices" not in self.domain.env.domaindata["zeek"]:
            return content, False

        for n in self.domain.env.domaindata["zeek"]["notices"]:
            modname = n[0].split("::")[0]
            entries = content.setdefault(modname, [])
            entries.append([n[0], 0, n[1], n[2], "", "", ""])

        content = sorted(content.items())

        return content, False


class ZeekDomain(Domain):
    """Zeek domain."""

    name = "zeek"
    label = "Zeek"

    object_types = {
        "type": ObjType(_("type"), "type"),
        "native-type": ObjType(_("type"), "type"),
        "namespace": ObjType(_("namespace"), "namespace"),
        "id": ObjType(_("id"), "id"),
        "keyword": ObjType(_("keyword"), "keyword"),
        "enum": ObjType(_("enum"), "enum"),
        "attr": ObjType(_("attr"), "attr"),
        "field": ObjType(_("field"), "field"),
    }

    directives = {
        "type": ZeekType,
        "native-type": ZeekNativeType,
        "namespace": ZeekNamespace,
        "id": ZeekIdentifier,
        "keyword": ZeekKeyword,
        "enum": ZeekEnum,
        "attr": ZeekAttribute,
        "field": ZeekField,
    }

    roles = {
        "type": XRefRole(),
        "namespace": XRefRole(),
        "id": XRefRole(),
        "keyword": XRefRole(),
        "enum": XRefRole(),
        "attr": XRefRole(),
        "see": XRefRole(),
        "field": ZeekFieldXRefRole(),
    }

    indices = [
        ZeekNotices,
    ]

    initial_data = {
        "objects": {},  # fullname -> docname, objtype
    }

    def clear_doc(self, docname):
        to_delete = []

        for (typ, name), doc in self.data["objects"].items():
            if doc == docname:
                to_delete.append((typ, name))

        for typ, name in to_delete:
            del self.data["objects"][typ, name]

    def resolve_xref(self, env, fromdocname, builder, typ, target, node, contnode):
        objects = self.data["objects"]

        if typ == "see":
            if target not in self.data["idtypes"]:
                logger.warning(
                    '%s: unknown target for ":zeek:see:`%s`"', fromdocname, target
                )
                return []

            objtype = self.data["idtypes"][target]
            return make_refnode(
                builder,
                fromdocname,
                objects[objtype, target],
                objtype + "-" + target,
                contnode,
                target + " " + objtype,
            )
        elif typ == "field" and "$" not in target:
            # :zeek:field:`x` without a record type ends up just x, no ref.
            return []
        else:
            objtypes = self.objtypes_for_role(typ)

            for objtype in objtypes:
                if (objtype, target) in objects:
                    return make_refnode(
                        builder,
                        fromdocname,
                        objects[objtype, target],
                        objtype + "-" + target,
                        contnode,
                        target + " " + objtype,
                    )
                else:
                    logger.warning(
                        '%s: unknown target for ":zeek:%s:`%s`"',
                        fromdocname,
                        typ,
                        target,
                    )

    def get_objects(self):
        for (typ, name), docname in self.data["objects"].items():
            yield name, name, typ, docname, typ + "-" + name, 1

    def merge_domaindata(self, docnames, otherdata):
        """
        Merge domaindata in multiprocess mode.

        I'm quite unclear how the objects dict works out okay in single
        process mode. For example, the file_entropy() event is defined
        in scripts/base/bif/plugins/Zeek_FileEntropy.events.bif.zeek.rst
        *and* in script-reference/autogenerated-file-analyzer-index.rst.
        The current documentation refers to the first one for :zeek:see:.
        It seems in single process mode the reading sorts filenames and
        just uses the last highest sorting one. That ends-up being the one
        in scripts/base.

            In [4]: "script-reference/autogenerated" < "scripts/base"
            Out[4]: True

        """
        for target, data in otherdata.items():
            if target == "version":
                continue
            elif hasattr(data, "items"):
                target_data = self.env.domaindata["zeek"].setdefault(target, {})

                # Iterate manually over the elements for debugging
                for k, v in data.items():
                    if k not in target_data:
                        target_data[k] = v
                    else:
                        # The > comparison below updates the objects domaindata
                        # to filenames that sort higher. See comment above.
                        if isinstance(v, str):
                            if v > target_data[k]:
                                target_data[k] = v
                        else:
                            # Otherwise assume it's a dict and we can merge
                            # using update()
                            target_data[k].update(v)

            elif hasattr(data, "extend"):
                # notices are a list
                target_data = self.env.domaindata["zeek"].setdefault(target, [])
                target_data.extend(data)
            else:
                raise NotImplementedError(target, type(data))
