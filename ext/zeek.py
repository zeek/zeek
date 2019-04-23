"""
    The Zeek domain for Sphinx.
"""

def setup(Sphinx):
    Sphinx.add_domain(ZeekDomain)
    Sphinx.add_node(see)
    Sphinx.add_directive_to_domain('zeek', 'see', SeeDirective)
    Sphinx.connect('doctree-resolved', process_see_nodes)

from sphinx import addnodes
from sphinx.domains import Domain, ObjType, Index
from sphinx.locale import _
from sphinx.directives import ObjectDescription
from sphinx.roles import XRefRole
from sphinx.util.nodes import make_refnode
from sphinx import version_info

from sphinx.util import logging
logger = logging.getLogger(__name__)

from docutils import nodes
from docutils.parsers.rst import Directive
from docutils.parsers.rst import directives
from docutils.parsers.rst.roles import set_classes

class see(nodes.General, nodes.Element):
    refs = []

class SeeDirective(Directive):
    has_content = True

    def run(self):
        n = see('')
        n.refs = " ".join(self.content).split()
        return [n]

# Wrapper for creating a tuple for index nodes, staying backwards
# compatible to Sphinx < 1.4:
def make_index_tuple(indextype, indexentry, targetname, targetname2):
    if version_info >= (1, 4, 0, '', 0):
        return (indextype, indexentry, targetname, targetname2, None)
    else:
        return (indextype, indexentry, targetname, targetname2)

def process_see_nodes(app, doctree, fromdocname):
    for node in doctree.traverse(see):
        content = []
        para = nodes.paragraph()
        para += nodes.Text("See also:", "See also:")
        for name in node.refs:
            join_str = " "
            if name != node.refs[0]:
                join_str  = ", "
            link_txt = join_str + name;

            if name not in app.env.domaindata['zeek']['idtypes']:
                # Just create the text and issue warning
                logger.warning('%s: unknown target for ".. zeek:see:: %s"', fromdocname, name, location=node)
                para += nodes.Text(link_txt, link_txt)
            else:
                # Create a reference
                typ = app.env.domaindata['zeek']['idtypes'][name]
                todocname = app.env.domaindata['zeek']['objects'][(typ, name)]

                newnode = nodes.reference('', '')
                innernode = nodes.literal(_(name), _(name))
                newnode['refdocname'] = todocname
                newnode['refuri'] = app.builder.get_relative_uri(
                    fromdocname, todocname)
                newnode['refuri'] += '#' + typ + '-' + name
                newnode.append(innernode)
                para += nodes.Text(join_str, join_str)
                para += newnode

        content.append(para)
        node.replace_self(content)

class ZeekGeneric(ObjectDescription):
    def update_type_map(self, idname):
        if 'idtypes' not in self.env.domaindata['zeek']:
            self.env.domaindata['zeek']['idtypes'] = {}
        self.env.domaindata['zeek']['idtypes'][idname] = self.objtype

    def add_target_and_index(self, name, sig, signode):
        targetname = self.objtype + '-' + name
        if targetname not in self.state.document.ids:
            signode['names'].append(targetname)
            signode['ids'].append(targetname)
            signode['first'] = (not self.names)
            self.state.document.note_explicit_target(signode)

            objects = self.env.domaindata['zeek']['objects']
            key = (self.objtype, name)
            if ( key in objects and self.objtype != "id" and
                 self.objtype != "type" ):
                logger.warning('%s: duplicate description of %s %s, ' %
                        (self.env.docname, self.objtype, name) +
                        'other instance in ' +
                        self.env.doc2path(objects[key]),
                        self.lineno)
            objects[key] = self.env.docname
            self.update_type_map(name)

        indextext = self.get_index_text(self.objtype, name)
        if indextext:
            self.indexnode['entries'].append(make_index_tuple('single',
                                             indextext, targetname,
                                             targetname))

    def get_index_text(self, objectname, name):
        return _('%s (%s)') % (name, self.objtype)

    def handle_signature(self, sig, signode):
        signode += addnodes.desc_name("", sig)
        return sig

class ZeekNamespace(ZeekGeneric):
    def add_target_and_index(self, name, sig, signode):
        targetname = self.objtype + '-' + name
        if targetname not in self.state.document.ids:
            signode['names'].append(targetname)
            signode['ids'].append(targetname)
            signode['first'] = (not self.names)
            self.state.document.note_explicit_target(signode)

            objects = self.env.domaindata['zeek']['objects']
            key = (self.objtype, name)
            objects[key] = self.env.docname
            self.update_type_map(name)

        indextext = self.get_index_text(self.objtype, name)
        self.indexnode['entries'].append(make_index_tuple('single', indextext,
                                          targetname, targetname))
        self.indexnode['entries'].append(make_index_tuple('single',
                                          "namespaces; %s" % (sig),
                                          targetname, targetname))

    def get_index_text(self, objectname, name):
        return _('%s (namespace); %s') % (name, self.env.docname)

    def handle_signature(self, sig, signode):
        signode += addnodes.desc_name("", sig)
        return sig

class ZeekEnum(ZeekGeneric):
    def add_target_and_index(self, name, sig, signode):
        targetname = self.objtype + '-' + name
        if targetname not in self.state.document.ids:
            signode['names'].append(targetname)
            signode['ids'].append(targetname)
            signode['first'] = (not self.names)
            self.state.document.note_explicit_target(signode)

            objects = self.env.domaindata['zeek']['objects']
            key = (self.objtype, name)
            objects[key] = self.env.docname
            self.update_type_map(name)

        indextext = self.get_index_text(self.objtype, name)
        #self.indexnode['entries'].append(make_index_tuple('single', indextext,
        #                                  targetname, targetname))
        m = sig.split()

        if len(m) < 2:
            logger.warning("%s: zeek:enum directive missing argument(s)", self.env.docname)
            return

        if m[1] == "Notice::Type":
            if 'notices' not in self.env.domaindata['zeek']:
                self.env.domaindata['zeek']['notices'] = []
            self.env.domaindata['zeek']['notices'].append(
                                (m[0], self.env.docname, targetname))
        self.indexnode['entries'].append(make_index_tuple('single',
                                          "%s (enum values); %s" % (m[1], m[0]),
                                          targetname, targetname))

    def handle_signature(self, sig, signode):
        m = sig.split()
        name = m[0]
        signode += addnodes.desc_name("", name)
        return name

class ZeekIdentifier(ZeekGeneric):
    def get_index_text(self, objectname, name):
        return name

class ZeekKeyword(ZeekGeneric):
    def get_index_text(self, objectname, name):
        return name

class ZeekAttribute(ZeekGeneric):
    def get_index_text(self, objectname, name):
        return _('%s (attribute)') % (name)

class ZeekNotices(Index):
    """
    Index subclass to provide the Zeek notices index.
    """

    name = 'noticeindex'
    localname = _('Zeek Notice Index')
    shortname = _('notices')

    def generate(self, docnames=None):
        content = {}

        if 'notices' not in self.domain.env.domaindata['zeek']:
            return content, False

        for n in self.domain.env.domaindata['zeek']['notices']:
            modname = n[0].split("::")[0]
            entries = content.setdefault(modname, [])
            entries.append([n[0], 0, n[1], n[2], '', '', ''])

        content = sorted(content.items())

        return content, False

class ZeekDomain(Domain):
    """Zeek domain."""
    name = 'zeek'
    label = 'Zeek'

    object_types = {
        'type':             ObjType(_('type'),             'type'),
        'namespace':        ObjType(_('namespace'),        'namespace'),
        'id':               ObjType(_('id'),               'id'),
        'keyword':          ObjType(_('keyword'),          'keyword'),
        'enum':             ObjType(_('enum'),             'enum'),
        'attr':             ObjType(_('attr'),             'attr'),
    }

    directives = {
        'type':             ZeekGeneric,
        'namespace':        ZeekNamespace,
        'id':               ZeekIdentifier,
        'keyword':          ZeekKeyword,
        'enum':             ZeekEnum,
        'attr':             ZeekAttribute,
    }

    roles = {
        'type':             XRefRole(),
        'namespace':        XRefRole(),
        'id':               XRefRole(),
        'keyword':          XRefRole(),
        'enum':             XRefRole(),
        'attr':             XRefRole(),
        'see':              XRefRole(),
    }

    indices = [
        ZeekNotices,
    ]

    initial_data = {
        'objects': {},  # fullname -> docname, objtype
    }

    def clear_doc(self, docname):
        to_delete = []

        for (typ, name), doc in self.data['objects'].items():
            if doc == docname:
                to_delete.append((typ, name))

        for (typ, name) in to_delete:
            del self.data['objects'][typ, name]

    def resolve_xref(self, env, fromdocname, builder, typ, target, node,
                     contnode):
        objects = self.data['objects']
        if typ == "see":
            if target not in self.data['idtypes']:
                logger.warning('%s: unknown target for ":zeek:see:`%s`"', fromdocname, target)
                return []
            objtype = self.data['idtypes'][target]
            return make_refnode(builder, fromdocname,
                                        objects[objtype, target],
                                        objtype + '-' + target,
                                        contnode, target + ' ' + objtype)
        else:
            objtypes = self.objtypes_for_role(typ)
            for objtype in objtypes:
                if (objtype, target) in objects:
                    return make_refnode(builder, fromdocname,
                                        objects[objtype, target],
                                        objtype + '-' + target,
                                        contnode, target + ' ' + objtype)
                else:
                    logger.warning('%s: unknown target for ":zeek:%s:`%s`"', fromdocname, typ, target)

    def get_objects(self):
        for (typ, name), docname in self.data['objects'].items():
            yield name, name, typ, docname, typ + '-' + name, 1
