#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='hvac',
    version='0.0.1',
    description='Hashicorp Vault API client'
    author='Ian Unruh',
    author_email='ianunruh@gmail.com',
    url='https://github.com/ianunruh/hvac',
    packages=find_packages(),
    install_requires=[
        'requests',
        'six',
    ],
)
