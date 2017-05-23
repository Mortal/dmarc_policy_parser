import logging
from dmarc_policy_parser import get_dmarc_policy
from dmarc_policy_parser.public_suffix import test as test_public_suffix


logging.basicConfig(level=logging.DEBUG)


for d in 'gmail.com hotmail.com google.com yahoo.com tdc.dk danskebank.dk'.split():
    print(d)
    try:
        print(get_dmarc_policy(d))
    except Exception as exn:
        print(repr(exn))

test_public_suffix()
