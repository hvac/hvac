#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='hvac',
    version='0.2.17',
    description='HashiCorp Vault API client',
    author='Ian Unruh',
    author_email='ianunruh@gmail.com',
    url='https://github.com/ianunruh/hvac',
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
