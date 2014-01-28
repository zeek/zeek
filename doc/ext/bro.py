"""
    The Bro domain for Sphinx.
"""

def setup(Sphinx):
    Sphinx.add_domain(BroDomain)
    Sphinx.add_node(see)
    Sphinx.add_directive_to_domain('bro', 'see', SeeDirective)
    Sphinx.connect('doctree-resolved', process_see_nodes)

from sphinx import addnodes
from sphinx.domains import Domain, ObjType, Index
from sphinx.locale import l_, _
from sphinx.directives import ObjectDescription
from sphinx.roles import XRefRole
from sphinx.util.nodes import make_refnode
import string

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
        n.refs = string.split(string.join(self.content))
        return [n]

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

            if name not in app.env.domaindata['bro']['idtypes']:
                # Just create the text and issue warning
                app.env.warn(fromdocname,
                             'unknown target for ".. bro:see:: %s"' % (name))
                para += nodes.Text(link_txt, link_txt)
            else:
                # Create a reference
                typ = app.env.domaindata['bro']['idtypes'][name]
                todocname = app.env.domaindata['bro']['objects'][(typ, name)]

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

class BroGeneric(ObjectDescription):
    def update_type_map(self, idname):
        if 'idtypes' not in self.env.domaindata['bro']:
            self.env.domaindata['bro']['idtypes'] = {}
        self.env.domaindata['bro']['idtypes'][idname] = self.objtype

    def add_target_and_index(self, name, sig, signode):
        targetname = self.objtype + '-' + name
        if targetname not in self.state.document.ids:
            signode['names'].append(targetname)
            signode['ids'].append(targetname)
            signode['first'] = (not self.names)
            self.state.document.note_explicit_target(signode)

            objects = self.env.domaindata['bro']['objects']
            key = (self.objtype, name)
            if ( key in objects and self.objtype != "id" and
                 self.objtype != "type" ):
                self.env.warn(self.env.docname,
                              'duplicate description of %s %s, ' %
                              (self.objtype, name) +
                              'other instance in ' +
                              self.env.doc2path(objects[key]),
                              self.lineno)
            objects[key] = self.env.docname
            self.update_type_map(name)

        indextext = self.get_index_text(self.objtype, name)
        if indextext:
            self.indexnode['entries'].append(('single', indextext,
                                              targetname, targetname))

    def get_index_text(self, objectname, name):
        return _('%s (%s)') % (name, self.objtype)

    def handle_signature(self, sig, signode):
        signode += addnodes.desc_name("", sig)
        return sig

class BroNamespace(BroGeneric):
    def add_target_and_index(self, name, sig, signode):
        targetname = self.objtype + '-' + name
        if targetname not in self.state.document.ids:
            signode['names'].append(targetname)
            signode['ids'].append(targetname)
            signode['first'] = (not self.names)
            self.state.document.note_explicit_target(signode)

            objects = self.env.domaindata['bro']['objects']
            key = (self.objtype, name)
            objects[key] = self.env.docname
            self.update_type_map(name)

        indextext = self.get_index_text(self.objtype, name)
        self.indexnode['entries'].append(('single', indextext,
                                          targetname, targetname))
        self.indexnode['entries'].append(('single',
                                          "namespaces; %s" % (sig),
                                          targetname, targetname))

    def get_index_text(self, objectname, name):
        return _('%s (namespace); %s') % (name, self.env.docname)

    def handle_signature(self, sig, signode):
        signode += addnodes.desc_name("", sig)
        return sig

class BroEnum(BroGeneric):
    def add_target_and_index(self, name, sig, signode):
        targetname = self.objtype + '-' + name
        if targetname not in self.state.document.ids:
            signode['names'].append(targetname)
            signode['ids'].append(targetname)
            signode['first'] = (not self.names)
            self.state.document.note_explicit_target(signode)

            objects = self.env.domaindata['bro']['objects']
            key = (self.objtype, name)
            objects[key] = self.env.docname
            self.update_type_map(name)

        indextext = self.get_index_text(self.objtype, name)
        #self.indexnode['entries'].append(('single', indextext,
        #                                  targetname, targetname))
        m = sig.split()

        if len(m) < 2:
            self.env.warn(self.env.docname,
                          "bro:enum directive missing argument(s)")
            return

        if m[1] == "Notice::Type":
            if 'notices' not in self.env.domaindata['bro']:
                self.env.domaindata['bro']['notices'] = []
            self.env.domaindata['bro']['notices'].append(
                                (m[0], self.env.docname, targetname))
        self.indexnode['entries'].append(('single',
                                          "%s (enum values); %s" % (m[1], m[0]),
                                          targetname, targetname))

    def handle_signature(self, sig, signode):
        m = sig.split()
        name = m[0]
        signode += addnodes.desc_name("", name)
        return name

class BroIdentifier(BroGeneric):
    def get_index_text(self, objectname, name):
        return name

class BroAttribute(BroGeneric):
    def get_index_text(self, objectname, name):
        return _('%s (attribute)') % (name)

class BroNotices(Index):
    """
    Index subclass to provide the Bro notices index.
    """

    name = 'noticeindex'
    localname = l_('Bro Notice Index')
    shortname = l_('notices')

    def generate(self, docnames=None):
        content = {}

        if 'notices' not in self.domain.env.domaindata['bro']:
            return content, False

        for n in self.domain.env.domaindata['bro']['notices']:
            modname = n[0].split("::")[0]
            entries = content.setdefault(modname, [])
            entries.append([n[0], 0, n[1], n[2], '', '', ''])

        content = sorted(content.iteritems())

        return content, False

class BroDomain(Domain):
    """Bro domain."""
    name = 'bro'
    label = 'Bro'

    object_types = {
        'type':             ObjType(l_('type'),             'type'),
        'namespace':        ObjType(l_('namespace'),        'namespace'),
        'id':               ObjType(l_('id'),               'id'),
        'enum':             ObjType(l_('enum'),             'enum'),
        'attr':             ObjType(l_('attr'),             'attr'),
    }

    directives = {
        'type':             BroGeneric,
        'namespace':        BroNamespace,
        'id':               BroIdentifier,
        'enum':             BroEnum,
        'attr':             BroAttribute,
    }

    roles = {
        'type':             XRefRole(),
        'namespace':        XRefRole(),
        'id':               XRefRole(),
        'enum':             XRefRole(),
        'attr':             XRefRole(),
        'see':              XRefRole(),
    }

    indices = [
        BroNotices,
    ]

    initial_data = {
        'objects': {},  # fullname -> docname, objtype
    }

    def clear_doc(self, docname):
        for (typ, name), doc in self.data['objects'].items():
            if doc == docname:
                del self.data['objects'][typ, name]

    def resolve_xref(self, env, fromdocname, builder, typ, target, node,
                     contnode):
        objects = self.data['objects']
        if typ == "see":
            if target not in self.data['idtypes']:
                self.env.warn(fromdocname,
                              'unknown target for ":bro:see:`%s`"' % (target))
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
                    self.env.warn(fromdocname,
                        'unknown target for ":bro:%s:`%s`"' % (typ, target))

    def get_objects(self):
        for (typ, name), docname in self.data['objects'].iteritems():
            yield name, name, typ, docname, typ + '-' + name, 1
