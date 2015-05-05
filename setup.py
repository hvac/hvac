#!/usr/bin/env python
from setuptools import setup, find_packages

setup(
    name='python-vaultclient',
    version='0.0.1',
    author='Ian Unruh',
    author_email='ianunruh@gmail.com',
    url='https://github.com/ianunruh/python-vaultclient',
    packages=find_packages(),
    install_requires=[
        'requests',
        'six',
    ],
)
