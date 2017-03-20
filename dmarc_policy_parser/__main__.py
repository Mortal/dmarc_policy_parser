from dmarc_policy_parser import get_dmarc_policy


for d in 'gmail.com hotmail.com google.com yahoo.com tdc.dk'.split():
    print(d)
    try:
        print(get_dmarc_policy(d))
    except Exception as exn:
        print(repr(exn))
