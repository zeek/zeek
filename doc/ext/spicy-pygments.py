# Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

from pygments.lexer import RegexLexer, bygroups, include, words
from pygments.token import (
    Comment,
    Keyword,
    Name,
    Number,
    Operator,
    Punctuation,
    String,
    Text,
)
from sphinx.highlighting import lexers


def setup(app):
    lexers["spicy"] = SpicyLexer()
    lexers["spicy-evt"] = SpicyEvtLexer()
    return {
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }


class SpicyLexer(RegexLexer):
    """
    For `Spicy <https://github.com/zeek/spicy>`_ grammars.
    """

    name = "Spicy"
    aliases = ["spicy"]
    filenames = ["*.spicy"]

    _hex = r"[0-9a-fA-F]"
    _float = r"((\d*\.?\d+)|(\d+\.?\d*))([eE][-+]?\d+)?"
    _h = r"[A-Za-z0-9][-A-Za-z0-9]*"
    _id = r"[a-zA-Z_][a-zA-Z_0-9]*"

    tokens = {
        "root": [
            include("whitespace"),
            include("comments"),
            include("directives"),
            include("attributes"),
            include("hooks"),
            include("properties"),
            include("types"),
            include("modules"),
            include("keywords"),
            include("literals"),
            include("operators"),
            include("punctuation"),
            include("function-call"),
            include("identifiers"),
        ],
        "whitespace": [
            (r"\n", Text),
            (r"\s+", Text),
            (r"\\\n", Text),
        ],
        "comments": [
            (r"#.*$", Comment),
        ],
        "directives": [(r"(@(if|else|endif))\b", Comment.Preproc)],
        "attributes": [
            (
                words(
                    (
                        "bit-order",
                        "byte-order",
                        "chunked",
                        "convert",
                        "count",
                        "cxxname",
                        "default",
                        "eod",
                        "internal",
                        "ipv4",
                        "ipv6",
                        "length",
                        "max-size",
                        "no-emit",
                        "nosub",
                        "on-heap",
                        "optional",
                        "originator",
                        "parse-at",
                        "parse-from",
                        "priority",
                        "requires",
                        "responder",
                        "size",
                        "static",
                        "synchronize",
                        "transient",
                        "try",
                        "type",
                        "until",
                        "until-including",
                        "while",
                        "have_prototype",
                    ),
                    prefix=r"&",
                    suffix=r"\b",
                ),
                Keyword.Pseudo,
            ),
        ],
        "hooks": [
            (
                rf"(on)(\s+)(({_id}::)+%?{_id}(\.{_id})*)",
                bygroups(Keyword, Text, Name.Function),
            ),
            (rf"(on)(\s+)(%?{_id}(\.{_id})*)", bygroups(Keyword, Text, Name.Function)),
        ],
        "properties": [
            # Like an ID, but allow hyphenation ('-')
            (r"%[a-zA-Z_][a-zA-Z_0-9-]*", Name.Attribute),
        ],
        "types": [
            (
                words(
                    (
                        "any",
                        "addr",
                        "bitfield",
                        "bool",
                        "bytes",
                        "__library_type",
                        "iterator",
                        "const_iterator",
                        "int8",
                        "int16",
                        "int32",
                        "int64",
                        "uint8",
                        "uint16",
                        "uint32",
                        "uint64",
                        "enum",
                        "interval",
                        "interval_ns",
                        "list",
                        "map",
                        "optional",
                        "port",
                        "real",
                        "regexp",
                        "set",
                        "sink",
                        "stream",
                        "view",
                        "string",
                        "time",
                        "time_ns",
                        "tuple",
                        "unit",
                        "vector",
                        "void",
                        "function",
                        "struct",
                    ),
                    prefix=r"\b",
                    suffix=r"\b",
                ),
                Keyword.Type,
            ),
            (
                rf"\b(type)(\s+)((?:{_id})(?:::(?:{_id}))*)\b",
                bygroups(Keyword, Text, Name.Class),
            ),
        ],
        "modules": [
            (
                rf"\b(import)(\s+)({_id})(\s+)(from)(\s+)(\S+)\b",
                bygroups(
                    Keyword.Namespace,
                    Text,
                    Name.Namespace,
                    Text,
                    Keyword.Namespace,
                    Text,
                    Name.Namespace,
                ),
            ),
            (
                rf"\b(module|import)(\s+)({_id})\b",
                bygroups(Keyword.Namespace, Text, Name.Namespace),
            ),
        ],
        "keywords": [
            (
                words(
                    ("global", "const", "local", "var", "public", "private", "inout"),
                    prefix=r"\b",
                    suffix=r"\b",
                ),
                Keyword.Declaration,
            ),
            (
                words(
                    (
                        "print",
                        "add",
                        "delete",
                        "stop",
                        "unset",
                        "assert",
                        "assert-exception",
                        "new",
                        "cast",
                        "begin",
                        "end",
                        "type",
                        "attribute",
                        "on",
                        "priority",
                        "if",
                        "else",
                        "switch",
                        "case",
                        "default",
                        "try",
                        "catch",
                        "break",
                        "return",
                        "continue",
                        "while",
                        "for",
                        "foreach",
                        "module",
                        "import",
                        "export",
                        "from",
                    ),
                    prefix=r"\b",
                    suffix=r"\b",
                ),
                Keyword,
            ),
        ],
        "literals": [
            (r'b?"', String, "string"),
            # Not the greatest match for patterns, but generally helps
            # disambiguate between start of a pattern and just a division
            # operator.
            (r"/(?=.*/)", String.Regex, "regex"),
            (r"\b(True|False|None|Null)\b", Keyword.Constant),
            # Port
            (r"\b\d{1,5}/(udp|tcp)\b", Number),
            # IPv4 Address
            (
                r"\b(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\b",
                Number,
            ),
            # IPv6 Address (not 100% correct: that takes more effort)
            (
                r"\[([0-9a-fA-F]{0,4}:){2,7}([0-9a-fA-F]{0,4})?((25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{1,2}))?\]",
                Number,
            ),
            # Numeric
            (rf"\b0[xX]{_hex}+\b", Number.Hex),
            (rf"\b{_float}\b", Number.Float),
            (r"\b(\d+)\b", Number.Integer),
        ],
        "operators": [
            (r"[$][$]", Name.Builtin.Pseudo),  # just-parsed-element
            (r"[$]\d+", Name.Builtin.Pseudo),  # capture-group
            (r"\b(in)\b", Operator.Word),
            (r"[-+*=&|<>.]{2}", Operator),
            (r"[-+*/=!><]=", Operator),
            (r"[?][.]", Operator),
            (r"[.][?]", Operator),
            (r"[-][>]", Operator),
            (r"[!][<>]", Operator),
            (r"[!%*/+<=>~|&^-]", Operator),
            # Technically, colons are often used for punctuation/sepration.
            # E.g. field name/type separation.
            (r"[?:]", Operator),
        ],
        "punctuation": [
            (r"[{}()\[\],;:.]", Punctuation),
        ],
        "function-call": [
            (rf"\b((?:{_id})(?:::(?:{_id}))*)(?=\s*\()", Name.Function),
        ],
        "identifiers": [
            (r"\b(self)\b", Name.Builtin.Pseudo),
            (r"([a-zA-Z_]\w*)(::)", bygroups(Name, Punctuation)),
            (r"[a-zA-Z_]\w*", Name),
        ],
        "string": [
            (r"\\.", String.Escape),
            (r"%-?[0-9]*(\.[0-9]+)?[DTdxsefg]", String.Escape),
            (r'"', String, "#pop"),
            (r".", String),
        ],
        "regex": [
            (r"\\.", String.Escape),
            (r"/", String.Regex, "#pop"),
            (r".", String.Regex),
        ],
    }


class SpicyEvtLexer(RegexLexer):
    """
    For `Spicy <https://github.com/zeek/spicy>`_ Zeek interface definitions.
    """

    name = "SpicyEvt"
    aliases = ["spicy-evt"]
    filenames = ["*.evt"]

    _id = r"[a-zA-Z_][a-zA-Z_0-9]*"

    tokens = {
        "root": [
            include("whitespace"),
            include("comments"),
            include("directives"),
            include("hooks"),
            include("modules"),
            include("keywords"),
            include("literals"),
            include("operators"),
            include("punctuation"),
            include("function-call"),
            include("identifiers"),
        ],
        "whitespace": SpicyLexer.tokens["whitespace"],
        "comments": SpicyLexer.tokens["comments"],
        "directives": SpicyLexer.tokens["directives"],
        "hooks": SpicyLexer.tokens["hooks"],
        "modules": SpicyLexer.tokens["modules"],
        "keywords": [
            (
                rf"\b(analyzer|with|replaces)(\s+)({_id}(::{_id})*)",
                bygroups(Keyword, Text, Name.Class),
            ),
            (
                words(("protocol", "packet", "file"), prefix=r"\b", suffix=r"\b"),
                Keyword.Type,
            ),
            (
                words(
                    ("port", "event", "parse", "over", "mime-type"),
                    prefix=r"\b",
                    suffix=r"\b",
                ),
                Keyword,
            ),
            (words(("cast"), prefix=r"\b", suffix=r"\b"), Keyword),
            (
                words(
                    (
                        "if",
                        "else",
                        "switch",
                        "case",
                        "default",
                        "try",
                        "catch",
                        "break",
                        "return",
                        "continue",
                        "while",
                        "for",
                        "foreach",
                    ),
                    prefix=r"\b",
                    suffix=r"\b",
                ),
                Keyword,
            ),
        ],
        "literals": SpicyLexer.tokens["literals"],
        "operators": SpicyLexer.tokens["operators"],
        "punctuation": SpicyLexer.tokens["punctuation"],
        "function-call": SpicyLexer.tokens["function-call"],
        "identifiers": [
            (r"\b(ZEEK_VERSION)\b", Name.Builtin),
            (r"\b(self)\b", Name.Builtin.Pseudo),
            (r"[$](conn|file|is_orig)", Name.Builtin.Pseudo),
            (r"([a-zA-Z_]\w*)(::)", bygroups(Name, Punctuation)),
            (r"[a-zA-Z_]\w*", Name),
        ],
        "string": SpicyLexer.tokens["string"],
        "regex": SpicyLexer.tokens["regex"],
    }
