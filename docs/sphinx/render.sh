#!/bin/bash
rm output/*
sphinx-apidoc -o ./output ../../ ../../setup.py
make clean
make html
