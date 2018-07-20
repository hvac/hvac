#!/usr/bin/env python
import os
import sys
from setuptools import setup, find_packages
from pkg_resources import resource_filename

with open("README.md", "r") as fh:
    long_description = fh.read()

# depending on your execution context the version file
# may be located in a different place!
vsn_path = resource_filename(__name__, 'hvac/version')
if not os.path.exists(vsn_path):
    vsn_path = resource_filename(__name__, 'version')
    if not os.path.exists(vsn_path):
        print("%s is missing" % vsn_path)
        sys.exit(1)

setup(
    name='hvac',
    version=open(vsn_path, 'r').read(),
    description='HashiCorp Vault API client',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Ian Unruh',
    author_email='ianunruh@gmail.com',
    url='https://github.com/hvac/hvac',
    keywords=['hashicorp', 'vault'],
    classifiers=['License :: OSI Approved :: Apache Software License'],
    packages=find_packages(),
    install_requires=[
        'requests>=2.7.0',
    ],
    include_package_data=True,
    package_data={'hvac': ['version']},
    extras_require={
        'parser': ['pyhcl>=0.2.1,<0.3.0']
    }
)
