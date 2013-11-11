# vim: set fileencoding=utf-8 sw=4 ts=4 et :

from rfc6266 import (
    parse_headers, parse_httplib2_response, parse_requests_response,
    build_header)
import pytest


def test_parsing():
    assert parse_headers(None).disposition == 'inline'
    assert parse_headers('attachment').disposition == 'attachment'
    assert parse_headers('attachment; key=val').assocs['key'] == 'val'
    assert parse_headers(
        'attachment; filename=simple').filename_unsafe == 'simple'

    # test ISO-8859-1
    fname = parse_headers(u'attachment; filename="oyé"').filename_unsafe
    assert fname == u'oyé', repr(fname)

    cd = parse_headers(
        'attachment; filename="EURO rates";'
        ' filename*=utf-8\'\'%e2%82%ac%20rates')
    assert cd.filename_unsafe == u'€ rates'


@pytest.mark.skipif("(3,0) <= sys.version_info < (3,3)")
def test_httplib2(httpserver):
    httplib2 = pytest.importorskip('httplib2')
    http = httplib2.Http()
    httpserver.serve_content('eep', headers={
        'Content-Disposition': 'attachment; filename="a b="'})
    resp, content = http.request(httpserver.url)
    assert parse_httplib2_response(resp).filename_unsafe == 'a b='


@pytest.mark.skipif("(3,0) <= sys.version_info < (3,3)")
def test_requests(httpserver):
    requests = pytest.importorskip('requests')
    httpserver.serve_content('eep', headers={
        'Content-Disposition': 'attachment; filename="a b="'})
    resp = requests.get(httpserver.url)
    assert parse_requests_response(resp).filename_unsafe == 'a b='


def test_location_fallback():
    assert parse_headers(
        None, location='https://foo/bar%c3%a9.py'
    ).filename_unsafe == u'baré.py'

    assert parse_headers(
        None, location='https://foo/'
    ).filename_unsafe == u''

    assert parse_headers(
        None, location='https://foo/%C3%A9toil%C3%A9/'
    ).filename_unsafe == u'étoilé'


def test_strict():
    # Trailing ; means the header is rejected
    assert parse_headers('attachment;').disposition == 'inline'
    assert parse_headers('attachment; key=val;').disposition == 'inline'
    try:
        cd = parse_headers(
            'attachment; filename="spa  ced";')
    except ValueError:
        assert True
    else:
        assert False, cd


def test_relaxed():
    assert parse_headers(
        'attachment;', relaxed=True).disposition == 'attachment'
    assert parse_headers(
        'attachment; key=val;', relaxed=True).disposition == 'attachment'
    cd = parse_headers(
        'attachment; filename="spa  ced";',
        relaxed=True)
    assert cd.filename_unsafe == u'spa ced'



def test_roundtrip():
    def roundtrip(filename):
        return parse_headers(build_header(filename)).filename_unsafe

    def assert_roundtrip(filename):
        assert roundtrip(filename) == filename

    assert_roundtrip('a b')
    assert_roundtrip('a   b')
    assert_roundtrip('a b ')
    assert_roundtrip(' a b')
    assert_roundtrip('a\"b')
    assert_roundtrip(u'aéio   o♥u"qfsdf!')

