#!/bin/bash

docker build . -t mod_evasive || exit 1
docker run --name mod_evasive_test -t -d -p 1980:80 mod_evasive
./test/test.pl
docker stop mod_evasive_test && docker rm mod_evasive_test
docker run --rm -t -v `pwd`/dist:/opt/jvdmr/apache2/mod_evasive/dist mod_evasive bash debian-build.sh
