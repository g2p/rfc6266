"""
"""

from lepl import *
from collections import namedtuple
from urllib import unquote
from string import hexdigits
import re

__all__ = ('parse_header', )


separator_chars = "()<>@,;:\\\"/[]?={} \t"
non_attr_chars = separator_chars + "*'%"

LangTagged = namedtuple('LangTagged', 'string langtag')


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
        disposition_parm = (ext_token & '=' & ext_value ) | (noext_token & '=' & value)
        disposition_type = Literal('inline') | Literal('attachment') | token
        content_disposition_value = disposition_type & Star(';' & disposition_parm)



class ContentDisposition(object):
    # inline indicates default processing
    disposition = 'inline'
    filename = None
    extra_parms = None


def parse_header(hdrval):
    # Require hdrval to be ascii bytes (0-127),
    # or characters in the ascii range
    hdrval = hdrval.encode('ascii')
    #content_disposition_value.config.clear().record_deepest()

    return content_disposition_value.parse(hdrval)


def selftest():
    sys.stderr.write('%s\n' % disposition_parm.parse('a=b'))
    sys.stderr.write('%s\n' % parse_header('attachment'))
    sys.stderr.write('%s\n' % parse_header('attachment; a=b'))
    sys.stderr.write('%s\n' % parse_header('attachment; filename=simple'))
    sys.stderr.write('%s\n' % parse_header('attachment; filename="EURO rates"; filename*=utf-8\'\'%e2%82%ac%20rates'))


if __name__ == '__main__':
    import sys
    sys.exit(selftest())

