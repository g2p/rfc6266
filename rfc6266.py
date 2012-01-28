# vim: set fileencoding=utf-8 sw=4 ts=4 et :

"""
"""

from lepl import *
from collections import namedtuple
from urllib import unquote
from string import hexdigits
import re

__all__ = ('ContentDisposition', )


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

    @property
    def is_inline(self):
        # According to the RFC, unknown dispositions should
        # be handled as attachments; receivers should look at
        # (not is_inline) unless they plan to handle non-standard
        # dispositions.
        return self.disposition == 'inline'


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


# To debug, wrap in this block:
#with TraceVariables():

separator_chars = "()<>@,;:\\\"/[]?={} \t"
ctl_chars = ''.join(chr(i) for i in xrange(32)) + chr(127)
nontoken_chars = separator_chars + ctl_chars

# Definitions from https://tools.ietf.org/html/rfc2616#section-2.2
token = AnyBut(nontoken_chars)[1:, ...]

# RFC 2616 says some linear whitespace (LWS) is in fact allowed in text
# and qdtext; however it also mentions folding that whitespace into
# a single SP (which isn't in CTL).
# Assume the caller already that folding when parsing headers.
qdtext = AnyBut('"' + ctl_chars)

char = Any(''.join(chr(i) for i in xrange(128)))  # ascii range: 0-127

quoted_pair = Drop('\\') + char
quoted_string = Drop('"') & (quoted_pair | qdtext)[:, ...] & Drop('"')

value = token | quoted_string

# Other charsets are forbidden, the spec reserves them
# for future evolutions.
charset = (CaseInsensitiveLiteral('UTF-8')
           | CaseInsensitiveLiteral('ISO-8859-1'))
# XXX See RFC 5646 for the correct definition
language = token
attr_char = AnyBut(nontoken_chars + "*'%")
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


def is_token_char(ch):
    # Must be ascii, and neither a control char nor a separator char
    asciicode = ord(ch)
    # < 128 means ascii, exclude control chars at 0-31 and 127,
    # exclude separator characters.
    return 31 < asciicode < 127 and ch not in separator_chars


def is_token(candidate):
    return all(is_token_char(ch) for ch in candidate)


def header_for_filename(filename, filename_ascii=None):
    if is_token(filename):
        return 'attachment; filename=%s' % filename

    try:
        asc = filename.encode('ascii')
        iso = filename.encode('iso-8859-1')
    except UnicodeEncodeError:
        return 'attachment; filename=%s; filename*=%s' % (fn1, fn2)
    else:
        # The filename is ascii already
        pass


def test_cdfh():
    cdfh = ContentDisposition.from_header
    assert ContentDisposition().disposition == 'inline'
    assert cdfh('attachment').disposition == 'attachment'
    assert cdfh('attachment; a=b').assocs['a'] == 'b'
    assert cdfh('attachment; filename=simple').filename == 'simple'
    cd = cdfh(
        'attachment; filename="EURO rates"; filename*=utf-8\'\'%e2%82%ac%20rates')
    assert cd.filename == u'€ rates'


