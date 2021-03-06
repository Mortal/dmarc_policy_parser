import os
import time
import logging
import urllib.error
import urllib.request

from dmarc_policy_parser.files import get_path
from dmarc_policy_parser.exceptions import DmarcException


logger = logging.getLogger('dmarc_policy_parser')


def download_file(uri, path, timeout=10):
    start_time = time.time()
    try:
        p = urllib.request.urlopen(uri, None, timeout)
    except urllib.error.URLError as exn:
        raise DmarcException('Could not download file') from exn
    tmp_path = path + '.tmp'
    try:
        fp = open(tmp_path, 'wb')
    except Exception as exn:
        p.close()
        raise DmarcException('Could not open output file') from exn
    try:
        try:
            size = int(p.getheader('Content-Length'))
        except (KeyError, ValueError):
            size = None
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time > timeout:
                raise DmarcException('download_file timed out')
            b = p.read(4096)
            if not b:
                break
            fp.write(b)
    finally:
        p.close()
        fp.close()
    try:
        os.rename(tmp_path, path)
    except Exception as exn:
        raise DmarcException('Could not rename temporary file') from exn


def fetch_public_suffixes(filename):
    download_file('https://raw.githubusercontent.com/publicsuffix/list/' +
                  'master/public_suffix_list.dat', filename)


def get_public_suffixes(max_age=7*24*3600):
    now = time.time()
    try:
        cache_age = now - get_public_suffixes._cache_time
    except AttributeError:
        cache_age = None
    if cache_age is not None and cache_age < max_age:
        return get_public_suffixes._cache

    filename = get_path('public_suffix_list.dat')
    try:
        file_mtime = os.stat(filename).st_mtime
    except FileNotFoundError:
        fetch_public_suffixes(filename)
    else:
        file_age = now - file_mtime
        if file_age > max_age:
            logger.info('Downloading new list of public suffixes')
            fetch_public_suffixes(filename)

    exceptions = set()
    rules = set()

    with open(filename) as fp:
        for line in fp:
            try:
                w = line.split()[0]
            except IndexError:
                continue
            if w != '//':
                # Specification says wildcards may be used in exotic ways,
                # but current data only has them in the first position.
                assert '*' not in w[1:]
                if w[0] == '!':
                    exceptions.add(w[1:])
                else:
                    rules.add(w)

    get_public_suffixes._cache = rules, exceptions
    get_public_suffixes._cache_time = now
    return rules, exceptions


def get_public_suffix(domain):
    if domain is None:
        return
    domain = domain.lower()
    rules, exceptions = get_public_suffixes()

    parts_input = domain.split('.')
    if not all(parts_input):
        # Some components are empty
        return
    # Decode punycode
    parts = [p[4:].encode().decode('punycode')
             if p.startswith('xn--') else p
             for p in parts_input]
    for i in range(len(parts)):
        current_suffix = '.'.join(parts[i:])
        # Is current_suffix a public suffix?
        if current_suffix in exceptions:
            return '.'.join(parts_input[i:])
        current_suffix_wild = '.'.join(['*'] + parts[i+1:])
        rule_matches = (
            i == len(parts) - 1 or
            current_suffix in rules or
            current_suffix_wild in rules)
        if rule_matches:
            if i > 0:
                return '.'.join(parts_input[i-1:])
            else:
                return


def test():
    # From https://github.com/publicsuffix/list/blob/master/tests/test_psl.txt
    tests = [
        # null input.
        (None, None),
        # Mixed case.
        ('COM', None),
        ('example.COM', 'example.com'),
        ('WwW.example.COM', 'example.com'),
        # Leading dot.
        ('.com', None),
        ('.example', None),
        ('.example.com', None),
        ('.example.example', None),
        # Unlisted TLD.
        ('example', None),
        ('example.example', 'example.example'),
        ('b.example.example', 'example.example'),
        ('a.b.example.example', 'example.example'),
        # Listed, but non-Internet, TLD.
        # ('local', None),
        # ('example.local', None),
        # ('b.example.local', None),
        # ('a.b.example.local', None),
        # TLD with only 1 rule.
        ('biz', None),
        ('domain.biz', 'domain.biz'),
        ('b.domain.biz', 'domain.biz'),
        ('a.b.domain.biz', 'domain.biz'),
        # TLD with some 2-level rules.
        ('com', None),
        ('example.com', 'example.com'),
        ('b.example.com', 'example.com'),
        ('a.b.example.com', 'example.com'),
        ('uk.com', None),
        ('example.uk.com', 'example.uk.com'),
        ('b.example.uk.com', 'example.uk.com'),
        ('a.b.example.uk.com', 'example.uk.com'),
        ('test.ac', 'test.ac'),
        # TLD with only 1 (wildcard) rule.
        ('mm', None),
        ('c.mm', None),
        ('b.c.mm', 'b.c.mm'),
        ('a.b.c.mm', 'b.c.mm'),
        # More complex TLD.
        ('jp', None),
        ('test.jp', 'test.jp'),
        ('www.test.jp', 'test.jp'),
        ('ac.jp', None),
        ('test.ac.jp', 'test.ac.jp'),
        ('www.test.ac.jp', 'test.ac.jp'),
        ('kyoto.jp', None),
        ('test.kyoto.jp', 'test.kyoto.jp'),
        ('ide.kyoto.jp', None),
        ('b.ide.kyoto.jp', 'b.ide.kyoto.jp'),
        ('a.b.ide.kyoto.jp', 'b.ide.kyoto.jp'),
        ('c.kobe.jp', None),
        ('b.c.kobe.jp', 'b.c.kobe.jp'),
        ('a.b.c.kobe.jp', 'b.c.kobe.jp'),
        ('city.kobe.jp', 'city.kobe.jp'),
        ('www.city.kobe.jp', 'city.kobe.jp'),
        # TLD with a wildcard rule and exceptions.
        ('ck', None),
        ('test.ck', None),
        ('b.test.ck', 'b.test.ck'),
        ('a.b.test.ck', 'b.test.ck'),
        ('www.ck', 'www.ck'),
        ('www.www.ck', 'www.ck'),
        # US K12.
        ('us', None),
        ('test.us', 'test.us'),
        ('www.test.us', 'test.us'),
        ('ak.us', None),
        ('test.ak.us', 'test.ak.us'),
        ('www.test.ak.us', 'test.ak.us'),
        ('k12.ak.us', None),
        ('test.k12.ak.us', 'test.k12.ak.us'),
        ('www.test.k12.ak.us', 'test.k12.ak.us'),
        # IDN labels.
        ('食狮.com.cn', '食狮.com.cn'),
        ('食狮.公司.cn', '食狮.公司.cn'),
        ('www.食狮.公司.cn', '食狮.公司.cn'),
        ('shishi.公司.cn', 'shishi.公司.cn'),
        ('公司.cn', None),
        ('食狮.中国', '食狮.中国'),
        ('www.食狮.中国', '食狮.中国'),
        ('shishi.中国', 'shishi.中国'),
        ('中国', None),
        # Same as above, but punycoded.
        ('xn--85x722f.com.cn', 'xn--85x722f.com.cn'),
        ('xn--85x722f.xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn'),
        ('www.xn--85x722f.xn--55qx5d.cn', 'xn--85x722f.xn--55qx5d.cn'),
        ('shishi.xn--55qx5d.cn', 'shishi.xn--55qx5d.cn'),
        ('xn--55qx5d.cn', None),
        ('xn--85x722f.xn--fiqs8s', 'xn--85x722f.xn--fiqs8s'),
        ('www.xn--85x722f.xn--fiqs8s', 'xn--85x722f.xn--fiqs8s'),
        ('shishi.xn--fiqs8s', 'shishi.xn--fiqs8s'),
        ('xn--fiqs8s', None),
    ]
    for domain, expected in tests:
        v = get_public_suffix(domain)
        assert v == expected, (domain, expected, v)
