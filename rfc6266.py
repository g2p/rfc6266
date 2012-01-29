# vim: set fileencoding=utf-8 sw=4 ts=4 et :

"""
"""

from lepl import *
from collections import namedtuple
from urllib import quote, unquote
from string import hexdigits, ascii_letters, digits
import posixpath
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
            self.assocs = dict((key.lower(), val) for (key, val) in assocs)

    @property
    def filename(self):
        if 'filename*' in self.assocs:
            return self.assocs['filename*'].string
        # Allow None
        return self.assocs.get('filename')

    def filename_with_location_fallback(self, location):
        rv = self.filename
        if rv is not None:
            return rv
        # XXX Should location be %-decoded or anything?
        return posixpath.basename(location)

    def __str__(self):
        return '%s %s' % (self.disposition, self.assocs)

    def __repr__(self):
        return 'ContentDisposition(%r, %r)' % (self.disposition, self.assocs)

    @classmethod
    def from_header(cls, hdrval):
        # fallback so that filename_with_location_fallback is still usable
        # without a Content-Disposition header.
        if hdrval is None:
            return cls()

        # Require hdrval to be ascii bytes (0-127),
        # or characters in the ascii range
        # XXX We might allow non-ascii here (see the definition of qdtext),
        # but parsing it would still be ambiguous. OTOH, we might allow it
        # just so that the non-ambiguous filename* value does get parsed.
        hdrval = hdrval.encode('ascii')
        # Check the caller already did LWS-folding (normally done
        # when separating header names and values; RFC 2616 section 2.2
        # says it should be done before interpretation at any rate).
        # Since this is ascii the definition of space is known; I don't know
        # what Python's definition of space chars will be if we allow
        # iso-8859-1.
        # This check is a bit stronger that LWS folding, it will
        # remove CR and LF even if they aren't part of a CRLF.
        # However http doesn't allow isolated CR and LF in headers outside
        # of LWS.
        assert hdrval == ' '.join(hdrval.split())
        rv, = content_disposition_value.parse(hdrval)
        return rv

    @property
    def is_inline(self):
        # According to RFC 6266, unknown dispositions should
        # be handled as attachments; receivers should look at
        # (not is_inline) unless they plan to handle dispositions
        # that go beyond the spec.
        return self.disposition.lower() == 'inline'


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


# RFC 2616
separator_chars = "()<>@,;:\\\"/[]?={} \t"
ctl_chars = ''.join(chr(i) for i in xrange(32)) + chr(127)
nontoken_chars = separator_chars + ctl_chars

# RFC 5987
attr_chars_nonalnum = '!#$&+-.^_`|~'
attr_chars = ascii_letters + digits + attr_chars_nonalnum

# RFC 5987 gives this alternative construction of the token character class
token_chars = attr_chars + "*'%"


# To debug, wrap in this block:
#with TraceVariables():

# Definitions from https://tools.ietf.org/html/rfc2616#section-2.2
# token was redefined from attr_chars to avoid using AnyBut,
# which might include non-ascii octets.
token = Any(token_chars)[1:, ...]


# RFC 2616 says some linear whitespace (LWS) is in fact allowed in text
# and qdtext; however it also mentions folding that whitespace into
# a single SP (which isn't in CTL).
# Assume the caller already that folding when parsing headers.

# XXX qdtext also allows non-ascii, which might be
# parsed as ISO-8859-1 (but is ambiguous). We should probably reject it.
# Everything else in this grammar (including RFC 5987 ext values)
# is ascii-safe.
# Because of this, this is the only character class to use AnyBut,
# and all the others are defined with Any.
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

attr_char = Any(attr_chars)
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


def usesonlycharsfrom(candidate, chars):
    # Found that shortcut in urllib.quote
    return not candidate.rstrip(chars)


def is_token(candidate):
    return all(is_token_char(ch) for ch in candidate)


def header_for_filename(filename, compat='ignore', filename_compat=None):
    # Compat methods (fallback for receivers that can't handle filename*):
    # - ignore (give only filename*);
    # - strip accents using unicode's decomposing normalisations,
    # which can be done from unicode data (stdlib), and keep only ascii;
    # - use the ascii transliteration tables from Unidecode (PyPI);
    # - use iso-8859-1 (can't be handled by the caller then).
    # Ignore is the safest, and can be used to trigger a fallback
    # to the document location.

    # While this method exists, it could also sanitize the filename
    # by rejecting slashes or other weirdness that might upset a receiver.

    if compat != 'ignore':
        raise NotImplementedError

    if is_token(filename):
        return 'attachment; filename=%s' % filename

    return "attachment; filename*=utf-8''%s" % quote(
        filename.encode('utf-8'), safe=attr_chars_nonalnum)


def test_cdfh():
    cdfh = ContentDisposition.from_header
    assert ContentDisposition().disposition == 'inline'
    assert cdfh('attachment').disposition == 'attachment'
    assert cdfh('attachment; key=val').assocs['key'] == 'val'
    assert cdfh('attachment; filename=simple').filename == 'simple'
    cd = cdfh(
        'attachment; filename="EURO rates"; filename*=utf-8\'\'%e2%82%ac%20rates')
    assert cd.filename == u'€ rates'

    def roundtrip(filename):
        return ContentDisposition.from_header(
            header_for_filename(filename)).filename

    def assert_roundtrip(filename):
        assert roundtrip(filename) == filename

    assert_roundtrip(u'aéioou"qfsdf!')


