import os
from setuptools import find_packages, setup

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.dirname(os.path.abspath(__file__))))

with open('README.md') as readme:
    README = readme.read()

setup(
    name='dmarc_policy_parser',
    version='0.2',
    description='Parse DMARC Policies published in DNS',
    long_description=README,
    url='https://github.com/Mortal/dmarc_policy_parser',
    author='Mathias Rav',
    license='Beerware',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',

        'Intended Audience :: Developers',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    packages=find_packages(include=['dmarc_policy_parser']),
)
