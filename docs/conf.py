# Configuration file for the Sphinx documentation builder.


# -- Path setup --------------------------------------------------------------
# Set up import path to allow the autodoc extension to find the local module code.
import os
import sys

sys.path.insert(0, os.path.abspath(".."))


# -- Project information -----------------------------------------------------

project = "hvac"
copyright = "2018-2020, Ian Unruh, Jeffrey Hogan"
author = "Ian Unruh, Jeffrey Hogan"

# The short X.Y version
version = "2.0.0"
# The full version, including alpha/beta/rc tags
release = "2.0.0"


# -- General configuration ---------------------------------------------------

extensions = [
    "docs.ext.hvac_doctest",
    "sphinx.ext.autodoc",
    "sphinx.ext.coverage",
    "sphinx.ext.viewcode",
    "sphinx.ext.githubpages",
    "m2r2",
    "autodocsumm",
]

# https://github.com/CrossNox/m2r2/blob/0408d7acea843485d9ff42ee08a105a79f045493/m2r2.py#L675C27-L675C51
# https://github.com/CrossNox/m2r2/issues/30
# We use m2r primarily to convert the markdown changelog to RST, so we don't need named references.
# Since we may have multiple changelog entries refer to the same GitHub issue, and we use the same text
# to anchor it (GH-###), it would result in duplicate explicit target names.
m2r_anonymous_references = True

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

source_suffix = [".rst", ".md"]

# The master toctree document.
master_doc = "index"

language = None
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
pygments_style = "sphinx"


# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
html_context = {"no_skippy": True}
html_theme_options = {
    # Toc options
    "collapse_navigation": False,
}

# -- Options for HTMLHelp output ---------------------------------------------

# Output file base name for HTML help builder.
htmlhelp_basename = "hvacdoc"

# -- Options for Epub output -------------------------------------------------

# Bibliographic Dublin Core info.
epub_title = project
epub_author = author
epub_publisher = author
epub_copyright = copyright

# A list of files that should not be packed into the epub file.
epub_exclude_files = ["search.html"]

# -- doctest configuration -------------------------------------------------
if os.getenv("READ_THE_DOCS_BUILD") is not None:
    doctest_global_enabled = False

doctest_global_setup = """
import os
from pprint import pprint, pformat

import mock

import hvac
from tests import utils as test_utils
from tests.doctest import doctest_global_setup
from tests.utils.server_manager import ServerManager

client_cert_path = test_utils.get_config_file_path('client-cert.pem')
client_key_path = test_utils.get_config_file_path('client-key.pem')
server_cert_path = test_utils.get_config_file_path('server-cert.pem')

manager, mocker = doctest_global_setup()
client = manager.client
"""

doctest_global_cleanup = """
mocker.stop()
manager.stop()
"""

# -- Autodoc configuration -------------------------------------------------

autodoc_default_options = {
    "autosummary": True,
}


def skip(app, what, name, obj, skip, options):
    """Method to override default autodoc skip call. Ensures class constructor
    (e.g., __init__()) methods are included regardless of if private methods
    are included in the documentation generally.
    """
    if name == "__init__":
        return False
    return skip


def setup(app):
    app.connect("autodoc-skip-member", skip)
