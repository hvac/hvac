#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='hvac',
    version='0.2.12',
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
)
