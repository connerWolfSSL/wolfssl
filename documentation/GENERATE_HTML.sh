#!/bin/sh

build/bin/doxygen Doxyfile

cp html_changes/* html/
cp html_changes/search/* html/search/
