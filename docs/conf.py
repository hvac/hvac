# -*- coding: utf-8 -*-
# Configuration file for the Sphinx documentation builder.


# -- Path setup --------------------------------------------------------------
# Set up import path to allow the autodoc extension to find the local module code.
import os
import sys
sys.path.insert(0, os.path.abspath('..'))


# -- Project information -----------------------------------------------------

project = u'hvac'
copyright = u'2018, Ian Unruh, Jeffrey Hogan'
author = u'Ian Unruh, Jeffrey Hogan'

# The short X.Y version
version = '0.7.1'
# The full version, including alpha/beta/rc tags
release = '0.7.1'


# -- General configuration ---------------------------------------------------

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.coverage',
    'sphinx.ext.viewcode',
    'sphinx.ext.githubpages',
    'm2r',
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

source_suffix = ['.rst', '.md']

# The master toctree document.
master_doc = 'index'

language = None
exclude_patterns = [u'_build', 'Thumbs.db', '.DS_Store']
pygments_style = 'sphinx'


# -- Options for HTML output -------------------------------------------------

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']


# -- Options for HTMLHelp output ---------------------------------------------

# Output file base name for HTML help builder.
htmlhelp_basename = 'hvacdoc'

# -- Options for Epub output -------------------------------------------------

# Bibliographic Dublin Core info.
epub_title = project
epub_author = author
epub_publisher = author
epub_copyright = copyright

# A list of files that should not be packed into the epub file.
epub_exclude_files = ['search.html']

# -- Autodoc configuration -------------------------------------------------


def skip(app, what, name, obj, skip, options):
    """Method to override default autodoc skip call. Ensures class constructor (e.g., __init__()) methods are included
    regardless of if private methods are included in the documentation generally.
    """
    if name == "__init__":
        return False
    return skip


def setup(app):
    app.connect("autodoc-skip-member", skip)
