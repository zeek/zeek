#! /usr/bin/env python

import os
import sys

from distutils.core import setup, Extension

setup(name="pybroccoli", 
    version="0.1",
    author="Robin Sommer",
    author_email="robin@icir.org",
    license="GPL",
    url="http://www.icir.org/robin/pybroccoli",
    py_modules=['broccoli'],
    ext_modules = [ 
        Extension("_broccoli_intern", ["broccoli_intern_wrap.c"],
                  include_dirs=["../../src"],
                  library_dirs=["../../src/.libs"],
                  libraries=["broccoli"])]
)

