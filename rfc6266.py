# vim: set fileencoding=utf-8 sw=4 ts=4 et :

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
            return self.assocs['filename*'].string
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
        rv, = content_disposition_value.parse(hdrval)
        return rv


def parse_ext_value(val):
    charset = val[0]
    if len(val) == 3:
        charset, langtag, coded = val
    else:
        charset, coded = val
        langtag = None
    decoded = coded.decode(charset)
    return LangTagged(decoded, langtag)


def parse_cdv(val):
    return ContentDisposition(disposition=val[0], assocs=val[1:])


# Currently LEPL doesn't handle case-insensivitity:
# https://groups.google.com/group/lepl/browse_thread/thread/68e7b136038772ca
def CaseInsensitiveLiteral(lit):
    return Regexp('(?i)' + re.escape(lit))


# To debug, use:
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
charset = (CaseInsensitiveLiteral('UTF-8')
           | CaseInsensitiveLiteral('ISO-8859-1'))
# XXX See RFC 5646 for the correct definition
language = token
attr_char = AnyBut(non_attr_chars)
hexdig = Any(hexdigits)
pct_encoded = '%' + hexdig + hexdig >> unquote
value_chars = (pct_encoded | attr_char)[...]
ext_value = (
    charset & Drop("'") & Optional(language) & Drop("'")
    & value_chars) > parse_ext_value
ext_token = token + '*'
noext_token = ~Lookahead(ext_token) & token

# Adapted/simplified from https://tools.ietf.org/html/rfc6266
with DroppedSpace():
    disposition_parm = (
        (ext_token & Drop('=') & ext_value)
        | (noext_token & Drop('=') & value)) > tuple
    disposition_type = Literal('inline') | Literal('attachment') | token
    content_disposition_value = (
        disposition_type & Star(Drop(';') & disposition_parm)) > parse_cdv


def test_cdfh():
    cdfh = ContentDisposition.from_header
    assert ContentDisposition().disposition == 'inline'
    assert cdfh('attachment').disposition == 'attachment'
    assert cdfh('attachment; a=b').assocs['a'] == 'b'
    assert cdfh('attachment; filename=simple').filename == 'simple'
    cd = cdfh(
        'attachment; filename="EURO rates"; filename*=utf-8\'\'%e2%82%ac%20rates')
    assert cd.filename == u'€ rates'


