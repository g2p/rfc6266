"""
"""

from lepl import *
from collections import namedtuple
from urllib import unquote
from string import hexdigits
import re

__all__ = ('ContentDisposition', )


separator_chars = "()<>@,;:\\\"/[]?={} \t"
non_attr_chars = separator_chars + "*'%"

LangTagged = namedtuple('LangTagged', 'string langtag')
Assoc = namedtuple('Assoc', 'variable value')


class ContentDisposition(object):
    def __init__(self, disposition='inline', assocs=None):
        self.disposition = disposition
        if assocs is None:
            self.assocs = {}
        else:
            # XXX Check that headers aren't repeated
            self.assocs = dict(assocs)

    @property
    def filename(self):
        if 'filename*' in self.assocs:
            return self.assocs['filename*']
        # Allow None
        return self.assocs.get('filename')

    def __str__(self):
        return '%s %s' % (self.disposition, self.assocs)

    def __repr__(self):
        return 'ContentDisposition(%r, %r)' % (self.disposition, self.assocs)

    @classmethod
    def from_header(cls, hdrval):
        # Require hdrval to be ascii bytes (0-127),
        # or characters in the ascii range
        hdrval = hdrval.encode('ascii')
        return content_disposition_value.parse(hdrval)



def parse_ext_value(val):
    charset = val[0]
    if len(val) == 3:
        charset, langtag, coded = val
    else:
        charset, coded = val
        langtag = None
    decoded = coded.decode(charset)
    return LangTagged(decoded, langtag)


def parse_assignment(val):
    return Assoc(*val)


def parse_cdv(val):
    return ContentDisposition(disposition=val[0], assocs=val[1:])


# Currently LEPL doesn't handle case-insensivitity:
# https://groups.google.com/group/lepl/browse_thread/thread/68e7b136038772ca
def case_insensitive_literal(lit):
    return Regexp('(?i)' + re.escape(lit))


if True:
#with TraceVariables():
    # Definitions from https://tools.ietf.org/html/rfc2616#section-2.2
    separator = Any(separator_chars)
    token = AnyBut(separator_chars)[1:, ...]
    qdtext = AnyBut('"')
    #char = Any(''.join(chr(i) for i in xrange(128)))  # ascii range: 0-127
    char = Any()  # we check for ascii before calling the parser
    quoted_pair = Drop('\\') + char
    quoted_string = Drop('"') & (quoted_pair | qdtext)[:, ...] & Drop('"')

    value = token | quoted_string

    # Other charsets are forbidden, the spec reserves them
    # for future evolutions.
    charset = case_insensitive_literal('UTF-8') | case_insensitive_literal('ISO-8859-1')
    # XXX See RFC 5646 for the correct definition
    language = token
    attr_char = AnyBut(non_attr_chars)
    hexdig = Any(hexdigits)
    pct_encoded = '%' + hexdig + hexdig >> unquote
    value_chars = (pct_encoded | attr_char)[...]
    ext_value = charset & Drop("'") & Optional(language) & Drop("'") & value_chars > parse_ext_value
    ext_token = token + '*'
    noext_token = ~Lookahead(ext_token) & token

    # Adapted/simplified from https://tools.ietf.org/html/rfc6266
    with DroppedSpace():
        disposition_parm = (ext_token & Drop('=') & ext_value ) | (noext_token & Drop('=') & value) > parse_assignment
        disposition_type = Literal('inline') | Literal('attachment') | token
        content_disposition_value = disposition_type & Star(Drop(';') & disposition_parm) > parse_cdv





def selftest():
    sys.stderr.write('%s\n' % disposition_parm.parse('a=b'))
    sys.stderr.write('%s\n' % ContentDisposition.from_header('attachment'))
    sys.stderr.write('%s\n' % ContentDisposition.from_header('attachment; a=b'))
    sys.stderr.write('%s\n' % ContentDisposition.from_header('attachment; filename=simple'))
    sys.stderr.write('%s\n' % ContentDisposition.from_header('attachment; filename="EURO rates"; filename*=utf-8\'\'%e2%82%ac%20rates'))


if __name__ == '__main__':
    import sys
    sys.exit(selftest())

