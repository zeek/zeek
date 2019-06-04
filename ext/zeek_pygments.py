from pygments.lexer import RegexLexer, bygroups, include, words, bygroups
from pygments.token import *

def setup(Sphinx):
    pass

class ZeekLexer(RegexLexer):
    """
    For `Zeek <https://www.zeek.org/>`_ scripts.

    .. versionadded:: 2.5
    """
    name = 'Zeek'
    aliases = ['zeek']
    filenames = ['*.zeek']

    _hex = r'[0-9a-fA-F]'
    _float = r'((\d*\.?\d+)|(\d+\.?\d*))([eE][-+]?\d+)?'
    _h = r'[A-Za-z0-9][-A-Za-z0-9]*'

    tokens = {
        'root': [
            include('whitespace'),
            include('comments'),
            include('directives'),
            include('attributes'),
            include('types'),
            include('keywords'),
            include('literals'),
            include('operators'),
            include('punctuation'),

            (r'\b((?:[A-Za-z_][A-Za-z_0-9]*)(?:::(?:[A-Za-z_][A-Za-z_0-9]*))*)(?=\s*\()',
                Name.Function),

            include('identifiers'),
        ],

        'whitespace': [
            (r'\n', Text),
            (r'\s+', Text),
            (r'\\\n', Text),
        ],

        'comments': [
            (r'#.*$', Comment),
        ],

        'directives': [
            (r'(@(load-plugin|load-sigs|load|unload))\b.*$', Comment.Preproc),
            (r'(@(DEBUG|DIR|FILENAME|deprecated|if|ifdef|ifndef|else|endif))\b', Comment.Preproc),
            (r'(@prefixes)\s*(\+?=).*$', Comment.Preproc),
        ],

        'attributes': [
            (words(('redef', 'priority', 'log', 'optional', 'default', 'add_func',
                    'delete_func', 'expire_func', 'read_expire', 'write_expire',
                    'create_expire', 'synchronized', 'persistent', 'rotate_interval',
                    'rotate_size', 'encrypt', 'raw_output', 'mergeable', 'error_handler',
                    'type_column', 'deprecated'),
                prefix=r'&', suffix=r'\b'),
             Keyword.Pseudo),
        ],

        'types': [
            (words(('any',
                    'enum', 'record', 'set', 'table', 'vector',
                    'function', 'hook', 'event',
                    'addr', 'bool', 'count', 'double', 'file', 'int', 'interval',
                    'pattern', 'port', 'string', 'subnet', 'time'),
                prefix=r'\b', suffix=r'\b'),
             Keyword.Type),

            (r'\b(opaque)(\s+)(of)(\s+)((?:[A-Za-z_][A-Za-z_0-9]*)(?:::(?:[A-Za-z_][A-Za-z_0-9]*))*)\b',
                bygroups(Keyword.Type, Text, Operator.Word, Text, Keyword.Type)),

            (r'\b(type)(\s+)((?:[A-Za-z_][A-Za-z_0-9]*)(?:::(?:[A-Za-z_][A-Za-z_0-9]*))*)(\s*)(:)(\s*)\b(record|enum)\b',
                bygroups(Keyword, Text, Name.Class, Text, Operator, Text, Keyword.Type)),

            (r'\b(type)(\s+)((?:[A-Za-z_][A-Za-z_0-9]*)(?:::(?:[A-Za-z_][A-Za-z_0-9]*))*)(\s*)(:)',
                bygroups(Keyword, Text, Name, Text, Operator)),

            (r'\b(redef)(\s+)(record|enum)(\s+)((?:[A-Za-z_][A-Za-z_0-9]*)(?:::(?:[A-Za-z_][A-Za-z_0-9]*))*)\b',
                bygroups(Keyword, Text, Keyword.Type, Text, Name.Class)),
        ],

        'keywords': [
            (words(('redef', 'export', 'if', 'else', 'for', 'while',
                    'return', 'break', 'next', 'continue', 'fallthrough',
                    'switch', 'default', 'case',
                    'add', 'delete',
                    'when', 'timeout', 'schedule'),
                prefix=r'\b', suffix=r'\b'),
             Keyword),
            (r'\b(print)\b', Keyword),
            (r'\b(global|local|const|option)\b', Keyword.Declaration),
            (r'\b(module)(\s+)(([A-Za-z_][A-Za-z_0-9]*)(?:::([A-Za-z_][A-Za-z_0-9]*))*)\b',
                bygroups(Keyword.Namespace, Text, Name.Namespace)),
        ],

        'literals': [
            (r'"', String, 'string'),

            # Not the greatest match for patterns, but generally helps
            # disambiguate between start of a pattern and just a division
            # operator.
            (r'/(?=.*/)', String.Regex, 'regex'),

            (r'\b(T|F)\b', Keyword.Constant),

            # Port
            (r'\b\d{1,5}/(udp|tcp|icmp|unknown)\b', Number),

            # IPv4 Address
            (r'\b(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\b', Number),

            # IPv6 Address (not 100% correct: that takes more effort)
            (r'\[([0-9a-fA-F]{0,4}:){2,7}([0-9a-fA-F]{0,4})?((25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2}))?\]', Number),

            # Numeric
            (r'\b0[xX]' + _hex + r'+\b', Number.Hex),
            (r'\b' + _float + r'\s*(day|hr|min|sec|msec|usec)s?\b', Literal.Date),
            (r'\b' + _float + r'\b', Number.Float),
            (r'\b(\d+)\b', Number.Integer),

            # Hostnames
            (_h + r'(\.' + _h + r')+', String),
        ],

        'operators': [
            (r'[!%*/+<=>~|&^-]', Operator),
            (r'([-+=&|]{2}|[+=!><-]=)', Operator),
            (r'\b(in|as|is|of)\b', Operator.Word),
            (r'\??\$', Operator),
            # Technically, colons are often used for punctuation/sepration.
            # E.g. field name/type separation.
            (r'[?:]', Operator),
        ],

        'punctuation': [
            (r'\?\$', Punctuation),
            (r'[{}()\[\],;:.]', Punctuation),
        ],

        'identifiers': [
            (r'([a-zA-Z_]\w*)(::)', bygroups(Name, Punctuation)),
            (r'[a-zA-Z_]\w*', Name)
        ],

        'string': [
            (r'\\.', String.Escape),
            (r'%-?[0-9]*(\.[0-9]+)?[DTdxsefg]', String.Escape),
            (r'"', String, '#pop'),
            (r'.', String),
        ],

        'regex': [
            (r'\\.', String.Escape),
            (r'/', String.Regex, '#pop'),
            (r'.', String.Regex),
        ],
    }
