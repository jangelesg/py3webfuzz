#!/usr/bin/env python
import io
import os
import sys

try:
    from setuptools import setup, find_packages

except:
    print(
        "You do not have setuptools installed. http://pypi.python.org/pypi/setuptools"
    )
    sys.exit(1)

VERSION = "0.1.6"

long_description_ = """py3webfuzz is a Python3 module to assist in the identification of vulnerabilities in web applications, 
Web Services through brute force and analysis methods. The module does this by providing common testing values, generators 
and other utilities that would be helpful when fuzzing web applications and API endpoints.

py3webfuzz has the fuzzdb and some other miscellaneous sources  implemented in Python classes, methods and functions for
ease of use. fuzzdb project is just a collection of values for testing. The point is to provide a pretty good selection
of values from fuzzdb project and some others miscellaneous sources, cleaned up and available through Python3 classes,
methods and namespaces. This makes it easier and handy when the time comes up to use these values in your own exploits and PoC.

Effort was made to match the names up similarly to the folders and values from the latest fuzzdb project. This effort can
sometimes make for some ugly looking namespaces. This balance was struck so that familiarity with the fuzzdb project
would cross over into the Python code. The exceptions come in with the replacement of hyphens with underscores.
"""

here = os.path.abspath(os.path.dirname(__file__))
# Import the README and use it as the long-description.
# Note: this will only work if 'README.md' is present in your MANIFEST.in file!
try:
    with io.open(os.path.join(here, 'README.md'), encoding='utf-8') as f:
        long_description = '\n' + f.read()
except FileNotFoundError:
    long_description = long_description

classifiers = [
    "Environment :: Web Environment",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3.8",
    "Topic :: Internet",
    "Topic :: Security"
]

#package_dir = {"py3webfuzz": "py3webfuzz"}

install_requires = [
    "requests",
    "bs4",
    "requests",
    "impacket",
    "urllib3"
]

setup(
    author="Jonathan Angeles",
    name="py3webfuzz",
    version=VERSION,
    author_email="jangelesg@gangsecurity.com",
    url="https://github.com/jangelesg/py3webfuzz",
    download_url="https://github.com/jangelesg/py3webfuzz/archive/{0}.tar.gz".format(VERSION),
    license="GPLv3",
    description="A Python3 module to assist in fuzzing web applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    #package_dir=package_dir,
    #packages=find_packages(exclude=("test",)),
    include_package_data=True,
    classifiers=classifiers,
    install_requires=install_requires,
    platforms=["Linux", "Windows", "macOs"],
    keywords='fuzz pentest security'

)
