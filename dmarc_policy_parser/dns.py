import os
import re
import json
import time
import logging
import subprocess
from dmarc_policy_parser.exceptions import DmarcException
from dmarc_policy_parser.files import get_path


logger = logging.getLogger('dmarc_policy_parser')


def fetch_dns_txt_record(domain, timeout=3):
    if domain.startswith('-'):
        raise ValueError('invalid domain %r' % (domain,))
    logger.info("Looking up %r", domain)
    proc = subprocess.Popen(
        ('host', '-t', 'TXT', domain),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    try:
        stdout_data, stderr_data = proc.communicate(None, timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        raise DmarcException('Timed out while looking up %r' % (domain,))
    if stderr_data:
        raise DmarcException('Error from host program: %r' %
                             (stderr_data[:500],))
    if b'not found' in stdout_data:
        if proc.returncode != 1:
            raise DmarcException(
                '"not found" in response, but host returned %s instead of 1' %
                proc.returncode)
        return None  # No such domain
    if proc.returncode != 0:
        raise DmarcException(
            '"not found" not in response, but host returned %s' %
            proc.returncode)
    try:
        stdout = stdout_data.decode('utf8')
    except UnicodeDecodeError:
        raise DmarcException('Could not decode host output %r' %
                             (stdout_data[:500],))
    records = []
    pattern = (
        r'^(\S+) (?:' +
        r'descriptive text "(.*)"|' +
        r'has no TXT record|' +
        r'is an alias for (?P<alias>\S+)\.)')

    clean_pattern = r'\\(.)|"\s*(.)'

    def repl(mo):
        if mo.group(1):
            return mo.group(1)
        elif mo.group(2) != '"':
            raise DmarcException(
                'Could not parse line %r' % (line[:500],))
        return ''

    current_domain = domain
    for line in stdout.splitlines():
        mo = re.match(pattern, line)
        if not mo:
            raise DmarcException('Could not parse line %r' % (line[:500],))
        domain_, record_escaped = mo.group(1, 2)
        if record_escaped is None:
            if mo.group('alias'):
                # is an alias for
                current_domain = mo.group('alias')
                continue
            else:
                # has no TXT record
                continue
        if domain_ != current_domain:
            raise DmarcException(
                'host program returned TXT record for %r, expected %r' %
                (domain_, current_domain))

        # Parse the output of host.
        # See lib/dns/rdata.c in bind. I think multitxt_totext is the one
        # that generates the output for "host -t TXT example.com",
        # in which case double quote, semi-colon, and backslash are
        # escaped with a backslash.
        record = re.sub(clean_pattern, repl, record_escaped)
        records.append(record)
    return records


def get_dns_txt_record(domain, timeout=3, max_age=24*3600):
    filename = get_path('dns_txt_cache.json')
    try:
        cache = get_dns_txt_record.cache
    except AttributeError:
        try:
            with open(filename) as fp:
                cache = get_dns_txt_record.cache = json.load(fp)
        except FileNotFoundError:
            cache = get_dns_txt_record.cache = {}

    now = time.time()
    if domain in cache:
        cached_result, cached_time = cache[domain]
        if cached_time >= now - max_age:
            return cached_result
    reraise_exn = None
    try:
        result = fetch_dns_txt_record(domain, timeout)
    except DmarcException as exn:
        reraise_exn = exn
        result = None
    cache[domain] = [result, now]
    tmp_filename = filename + '.tmp'
    with open(tmp_filename, 'w') as fp:
        json.dump(cache, fp, indent=0)
    os.rename(tmp_filename, filename)
    if reraise_exn:
        raise reraise_exn
    return result
