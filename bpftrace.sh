#!/bin/bash

set -x

pgrep helloworld || (echo "run helloworld first"; exit 1) &&
  sudo bpftrace -e 'uprobe:helloworld/helloworld:main.helloWorld { printf("%d\n", (int64)(sarg1)); }' $@

