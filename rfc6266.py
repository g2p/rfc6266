# vim: set fileencoding=utf-8 sw=4 ts=4 et :

"""Implements RFC 6266, the Content-Disposition HTTP header.

Currently only the receiver side is handled.
Sender side is a work in progress.
"""

from lepl import *
from collections import namedtuple
from urllib import quote, unquote
from string import hexdigits, ascii_letters, digits
import posixpath
import os.path
import re

__all__ = ('ContentDisposition', )


LangTagged = namedtuple('LangTagged', 'string langtag')


class ContentDisposition(object):
    """
    Records various indications and hints about content disposition.

    These can be used to know if a file should be downloaded or
    displayed directly, and to hint what filename it should have
    in the download case.
    """

    def __init__(self, disposition='inline', assocs=None, location=None):
        """This constructor is used internally after parsing the header.

        Instances should generally be created from a factory class
        method, such as from_headers and from_httplib2_response.
        """

        self.disposition = disposition
        self.location = location
        if assocs is None:
            self.assocs = {}
        else:
            # XXX Check that parameters aren't repeated
            self.assocs = dict((key.lower(), val) for (key, val) in assocs)

    @property
    def filename_unsafe(self):
        """The filename from the Content-Disposition header.

        If a location was passed at instanciation, the basename
        from that may be used as a fallback. Otherwise, this may
        be the None value.

        On safety:
            This property records the intent of the sender.

            You shouldn't use this sender-controlled value as a filesystem
        path, it can be insecure. Serving files with this filename can be
        dangerous as well, due to a certain browser using the part after the
        dot for mime-sniffing.
        Saving it to a database is fine by itself though.
        """

        if 'filename*' in self.assocs:
            return self.assocs['filename*'].string
        elif 'filename' in self.assocs:
            return self.assocs['filename']
        elif self.location is not None:
            # XXX Should that be %-decoded or anything?
            return posixpath.basename(self.location)

    def filename_sanitized(self, extension, default_filename='file'):
        """Returns a filename that is safer to use on the filesystem.

        The filename will not contain a slash (nor the path separator
        for the current platform, if different), it will not
        start with a dot, and it will have the expected extension.

        No guarantees that makes it "safe enough".
        No effort is made to remove special characters;
        using this value blindly might overwrite existing files, etc.
        """

        assert extension
        assert extension[0] != '.'
        assert default_filename
        assert '.' not in default_filename
        extension = '.' + extension

        fname = self.filename_unsafe
        if fname is None:
            fname = default_filename
        fname = posixpath.basename(fname)
        fname = os.path.basename(fname)
        fname = fname.lstrip('.')
        if not fname:
            fname = default_filename
        if not fname.endswith(extension):
            fname = fname + extension
        return fname

    @property
    def is_inline(self):
        """If this property is true, the file should be handled inline.

        Otherwise, and unless your application supports other dispositions
        than the standard inline and attachment, it should be handled
        as an attachment.
        """

        return self.disposition.lower() == 'inline'

    def __repr__(self):
        return 'ContentDisposition(%r, %r, %r)' % (
            self.disposition, self.assocs, self.location)

    @classmethod
    def from_headers(cls, content_disposition, location=None):
        """Build a ContentDisposition from header values.
        """

        if content_disposition is None:
            return cls(location=location)

        # Require content_disposition to be ascii bytes (0-127),
        # or characters in the ascii range
        # XXX We might allow non-ascii here (see the definition of qdtext),
        # but parsing it would still be ambiguous. OTOH, we might allow it
        # just so that the non-ambiguous filename* value does get parsed.
        content_disposition = content_disposition.encode('ascii')
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
        assert content_disposition == ' '.join(content_disposition.split())
        parsed = content_disposition_value.parse(content_disposition)
        return ContentDisposition(
            disposition=parsed[0], assocs=parsed[1:], location=location)

    @classmethod
    def from_httplib2_response(cls, response):
        """Build a ContentDisposition from an httplib2 response.
        """

        return cls.from_headers(
            response['content-disposition'], response['content-location'])


def parse_ext_value(val):
    charset = val[0]
    if len(val) == 3:
        charset, langtag, coded = val
    else:
        charset, coded = val
        langtag = None
    decoded = coded.decode(charset)
    return LangTagged(decoded, langtag)


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

# Adapted from https://tools.ietf.org/html/rfc6266
# Mostly this was simplified to fold filename / filename*
# into the normal handling of ext_token / noext_token
with DroppedSpace():
    disposition_parm = (
        (ext_token & Drop('=') & ext_value)
        | (noext_token & Drop('=') & value)) > tuple
    disposition_type = (
        CaseInsensitiveLiteral('inline')
        | CaseInsensitiveLiteral('attachment')
        | token)
    content_disposition_value = (
        disposition_type & Star(Drop(';') & disposition_parm))


def is_token_char(ch):
    # Must be ascii, and neither a control char nor a separator char
    asciicode = ord(ch)
    # < 128 means ascii, exclude control chars at 0-31 and 127,
    # exclude separator characters.
    return 31 < asciicode < 127 and ch not in separator_chars


def usesonlycharsfrom(candidate, chars):
    # Found that shortcut in urllib.quote
    return candidate.rstrip(chars) == ''


def is_token(candidate):
    return all(is_token_char(ch) for ch in candidate)


def header_for_filename(filename, disposition='attachment',
                        compat='ignore', filename_compat=None):
    # https://tools.ietf.org/html/rfc6266#appendix-D
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

    if disposition != 'attachment':
        assert is_token(disposition)

    if is_token(filename):
        return '%s; filename=%s' % (disposition, filename)

    return "%s; filename*=utf-8''%s" % (disposition, quote(
        filename.encode('utf-8'), safe=attr_chars_nonalnum))


def test_cdfh():
    cdfh = ContentDisposition.from_headers
    assert ContentDisposition().disposition == 'inline'
    assert cdfh('attachment').disposition == 'attachment'
    assert cdfh('attachment; key=val').assocs['key'] == 'val'
    assert cdfh('attachment; filename=simple').filename_unsafe == 'simple'
    cd = cdfh(
        'attachment; filename="EURO rates"; filename*=utf-8\'\'%e2%82%ac%20rates')
    assert cd.filename_unsafe == u'€ rates'

    def roundtrip(filename):
        return ContentDisposition.from_headers(
            header_for_filename(filename)).filename_unsafe

    def assert_roundtrip(filename):
        assert roundtrip(filename) == filename

    assert_roundtrip(u'aéioou"qfsdf!')


