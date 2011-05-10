"""
    The Bro domain for Sphinx.
"""

def setup(Sphinx):
    Sphinx.add_domain(BroDomain)

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

class BroGeneric(ObjectDescription):
    def add_target_and_index(self, name, sig, signode):
        targetname = self.objtype + '-' + name
        if targetname not in self.state.document.ids:
            signode['names'].append(targetname)
            signode['ids'].append(targetname)
            signode['first'] = (not self.names)
            self.state.document.note_explicit_target(signode)

            objects = self.env.domaindata['bro']['objects']
            key = (self.objtype, name)
# this is commented out mostly just to avoid having a special directive
# for events in order to avoid the duplicate warnings in that case
            """
            if key in objects:
                self.env.warn(self.env.docname,
                              'duplicate description of %s %s, ' %
                              (self.objtype, name) +
                              'other instance in ' +
                              self.env.doc2path(objects[key]),
                              self.lineno)
            """
            objects[key] = self.env.docname
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
        indextext = self.get_index_text(self.objtype, name)
        #self.indexnode['entries'].append(('single', indextext,
        #                                  targetname, targetname))
        m = sig.split()
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
    }

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
        objtypes = self.objtypes_for_role(typ)
        for objtype in objtypes:
            if (objtype, target) in objects:
                return make_refnode(builder, fromdocname,
                                    objects[objtype, target],
                                    objtype + '-' + target,
                                    contnode, target + ' ' + objtype)

    def get_objects(self):
        for (typ, name), docname in self.data['objects'].iteritems():
            yield name, name, typ, docname, typ + '-' + name, 1
