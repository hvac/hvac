#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='alooma-hvac',
    version='0.2.18',
    description='HashiCorp Vault API client',
    author='Ram Amar',
    author_email='rami@alooma.com',
    url='https://github.com/Aloomaio/alooma-hvac',
    keywords=['hashicorp', 'vault'],
    classifiers=['License :: OSI Approved :: Apache Software License'],
    packages=find_packages(),
    install_requires=[
        'requests>=2.7.0',
    ],
    extras_require = {
        'parser': ['pyhcl>=0.2.1,<0.3.0']
    }
)
