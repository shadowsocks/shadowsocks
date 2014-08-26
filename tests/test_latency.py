#!/usr/bin/python

import sys
import time


before = time.time()

for line in sys.stdin:
    if 'HTTP/1.1 ' in line:
        diff = time.time() - before
        print 'headline %dms' % (diff * 1000)
