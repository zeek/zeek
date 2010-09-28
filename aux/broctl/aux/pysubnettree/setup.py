#! /usr/bin/env python

import sys

from distutils.core import setup, Extension

setup(name="pysubnettree", 
    version="0.12",
    author="Robin Sommer",
    author_email="robin@icir.org",
    license="BSD",
    url="http://www.icir.org/robin/pysubnettree",
    py_modules=['SubnetTree'],
    ext_modules = [ 
        Extension("_SubnetTree", ["SubnetTree.cc", "patricia.c", "SubnetTree_wrap.cc"]), 
        ] 
)

