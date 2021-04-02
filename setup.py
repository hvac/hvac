#!/usr/bin/env python
from setuptools import setup, find_packages


def load_long_description():
    with open("README.md", "r") as fh:
        long_description = fh.read()
    return long_description


setup(
    name='hvac',
    version='0.10.9',
    description='HashiCorp Vault API client',
    long_description=load_long_description(),
    long_description_content_type="text/markdown",
    author='Ian Unruh <ianunruh@gmail.com>, Jeffrey Hogan <jeff.hogan1@gmail.com>',
    author_email='admin@python-hvac.org',
    url='https://github.com/hvac/hvac',
    keywords=['hashicorp', 'vault'],
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
    ],
    packages=find_packages(exclude=['docs*', 'tests*']),
    install_requires=[
        'requests>=2.21.0',
        'six>=1.5.0',
    ],
    include_package_data=True,
    package_data={'hvac': ['version']},
    extras_require={
        'parser': ['pyhcl>=0.3.10']
    }
)
