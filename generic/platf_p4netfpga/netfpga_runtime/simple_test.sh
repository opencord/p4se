#!/bin/bash

MYDIR=`dirname $(readlink -f $0)`
python $MYDIR/simple_test.py
