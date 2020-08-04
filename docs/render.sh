#!/bin/bash
rm modules.rst 
rm sendit.applications.rst
rm sendit.handlers.rst
rm sendit.helper_functions.rst
rm sendit.protocols.rst
rm sendit.rst
sphinx-apidoc -o . ../ ../setup.py
make clean
make html
