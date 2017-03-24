import re

from dmarc_policy_parser.exceptions import DmarcException
from dmarc_policy_parser.public_suffix import get_public_suffix
from dmarc_policy_parser.dns import get_dns_txt_record


DMARC_RECORD_PATTERN = '^\s*v\s*=\s*DMARC1\s*;.*$'


class _Parser:
    def __init__(self, record):
        self.is_dmarc_record = bool(re.match(DMARC_RECORD_PATTERN, record))
        # See https://tools.ietf.org/html/rfc7489#section-6.4
        component_strings = record.strip().split(';')
        if len(component_strings) == 0:
            raise ValueError('empty input')
        if component_strings[-1] == '':
            # Trailing separator allowed
            component_strings.pop()
        seen_idx = {}
        self.values = {}
        for i, s in enumerate(component_strings):
            try:
                k, v = s.split('=', 1)
            except ValueError:
                raise ValueError('missing "=" in component: %r' % (s,))
            k, v = k.strip(), v.strip()
            if seen_idx.setdefault(k, i) != i:
                raise ValueError('duplicate key %r' % (k,))
            if (i == 0) != (k == 'v'):
                assert not self.is_dmarc_record
                raise ValueError('version must be first')
            if k == 'r' and i != 1:
                raise ValueError('request must be second')
            try:
                method = getattr(self, 'parse_' + k)
            except AttributeError:
                raise ValueError('unrecognized component %r' % (k,))
            method(v)

    def set_value(self, k, v):
        self.values[k] = v

    # dmarc-version   = "v" *WSP "=" *WSP %x44 %x4d %x41 %x52 %x43 %x31
    def parse_v(self, value):
        if value != 'DMARC1':
            assert not self.is_dmarc_record
            raise ValueError('invalid version %r' % (value,))
        self.set_value('version', value)

    def _parse_request(self, value):
        if value not in ('none', 'quarantine', 'reject'):
            raise ValueError('invalid request %r' % (value,))
        return value

    # dmarc-request   = "p" *WSP "=" *WSP
    #                   ( "none" / "quarantine" / "reject" )
    def parse_p(self, value):
        self.set_value('request', self._parse_request(value))

    # dmarc-srequest  = "sp" *WSP "=" *WSP
    #                   ( "none" / "quarantine" / "reject" )
    def parse_sp(self, value):
        self.set_value('srequest', self._parse_request(value))

    def _parse_uri(self, value):
        r = []
        for v in value.split(':'):
            try:
                uri, limit_str = v.split('!', 1)
            except ValueError:
                uri, limit = v, None
            else:
                if not limit_str:
                    raise ValueError('empty size in %r' % (value,))
                sizes = dict(k=10, m=20, g=30, t=40)
                if limit_str[-1] in sizes:
                    limit = int(limit_str[:-1]) * 2 ** sizes[limit_str[-1]]
                else:
                    limit = int(limit_str)
            r.append((uri, limit))
        return r

    # dmarc-auri      = "rua" *WSP "=" *WSP
    #                   dmarc-uri *(*WSP "," *WSP dmarc-uri)
    def parse_rua(self, value):
        self.set_value('auri', self._parse_uri(value))

    # dmarc-furi      = "ruf" *WSP "=" *WSP
    #                   dmarc-uri *(*WSP "," *WSP dmarc-uri)
    def parse_ruf(self, value):
        self.set_value('furi', self._parse_uri(value))

    def _parse_alignment(self, value):
        if value not in ('r', 's'):
            raise ValueError('invalid alignment %r' % (value,))
        return value

    # dmarc-adkim     = "adkim" *WSP "=" *WSP
    #                   ( "r" / "s" )
    def parse_adkim(self, value):
        self.set_value('adkim', self._parse_alignment(value))

    # dmarc-aspf      = "aspf" *WSP "=" *WSP
    #                   ( "r" / "s" )
    def parse_aspf(self, value):
        self.set_value('aspf', self._parse_alignment(value))

    # dmarc-ainterval = "ri" *WSP "=" *WSP 1*DIGIT
    def parse_ri(self, value):
        self.set_value('ainterval', int(value))

    # dmarc-fo        = "fo" *WSP "=" *WSP
    #                   ( "0" / "1" / "d" / "s" )
    #                   *(*WSP ":" *WSP ( "0" / "1" / "d" / "s" ))
    def parse_fo(self, value):
        v_strip = re.sub(r'\s+', '', value)
        values = v_strip.split(':')
        if any(v not in ('0', '1', 'd', 's') for v in values):
            raise ValueError('invalid failure reporting options %r' % value)
        self.set_value('fo', values)

    # dmarc-rfmt      = "rf"  *WSP "=" *WSP Keyword *(*WSP ":" Keyword)
    #                   ; registered reporting formats only
    def parse_rf(self, value):
        self.set_value('rfmt', [c.strip() for c in value.split(':')])

    # dmarc-percent   = "pct" *WSP "=" *WSP
    #                   1*3DIGIT
    def parse_pct(self, value):
        self.set_value('percent', int(value))


def parse_dmarc_policy(record):
    return _Parser(record).values


def _get_dmarc_record(domain, *args, **kwargs):
    subdomain = '_dmarc.%s' % domain
    # The following call might raise DmarcException
    # in case of a runtime error in the DNS lookup
    records = get_dns_txt_record(subdomain, *args, **kwargs) or ()
    records = [r for r in records if re.match(DMARC_RECORD_PATTERN, r)]
    if records:
        if len(records) > 1:
            raise DmarcException(
                'more than one DMARC policy published for %r' % (domain,))
        try:
            result = parse_dmarc_policy(records[0])
        except ValueError as exn:
            raise DmarcException(
                'Could not parse record %r: %s' %
                (records[0], exn))
        result['domain'] = domain
        return result


def get_dmarc_record(domain, *args, **kwargs):
    '''
    Implements DMARC Policy Discovery [DMARC, Sec. 6.6.3].
    https://tools.ietf.org/html/rfc7489#section-6.6.3
    '''
    record = _get_dmarc_record(domain, *args, **kwargs)
    if not record:
        org_domain = get_public_suffix(domain)
        if org_domain != domain:
            record = _get_dmarc_record(org_domain, *args, **kwargs)
    return record


def get_dmarc_policy(domain, *args, **kwargs):
    POLICY = ['none', 'quarantine', 'reject']
    record = get_dmarc_record(domain, *args, **kwargs)
    if not record:
        return 'none'
    request = record.get('request')
    srequest = record.get('srequest')
    if record['domain'] != domain and srequest in POLICY:
        return srequest
    if request in POLICY:
        return request
    return 'none'
