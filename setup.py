#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ast
import io
import re
import os
from setuptools import find_packages, setup

DEPENDENCIES = ["boto3 >= 1.9.68", "requests"]
EXCLUDE_FROM_PACKAGES = ["contrib", "docs", "tests*"]
CURDIR = os.path.abspath(os.path.dirname(__file__))

with io.open(os.path.join(CURDIR, "README.md"), "r", encoding="utf-8") as f:
    README = f.read()


def get_version():
    """ Get version from main() """

    main_file = os.path.join(CURDIR, "opstools", "main.py")
    _version_re = re.compile(r"__version__\s+=\s+(?P<version>.*)")
    with open(main_file, "r", encoding="utf8") as version_file:
        match = _version_re.search(version_file.read())
        version = match.group("version") if match is not None else '"unknown"'
    return str(ast.literal_eval(version))


setup(
    name="opstools",
    version=get_version(),
    author="Afraz",
    author_email="afrazkhan@gmail.com",
    description="Opsy type tools I use everyday that you might find useful",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/afrazkhan/opstools",
    packages=find_packages(exclude=EXCLUDE_FROM_PACKAGES),
    include_package_data=True,
    keywords=[],
    scripts=[],
    entry_points={"console_scripts": ["opstools=opstools.main:main"]},
    zip_safe=False,
    install_requires=DEPENDENCIES,
    test_suite="tests.test_project",
    python_requires=">=3.6",
    # license and classifier list:
    # https://pypi.org/pypi?%3Aaction=list_classifiers
    license="License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    classifiers=[
        # "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        # "Private :: Do Not Upload"
    ],
)
