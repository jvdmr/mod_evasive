#!/bin/bash

for tp in test/*
do
	echo
	echo "Building test container"
	docker build . --target test --build-arg "test_path=${tp}" -t mod_evasive_test || exit 1
	echo "Starting test container"
	docker run --rm -t --name=mod_evasive_test -d -p 1980:80 mod_evasive_test
	echo "Running test"
	${tp}/test.sh
	echo "Stopping test container"
	docker kill mod_evasive_test
done

echo
echo "Building packaging container"
docker build . --target package -t mod_evasive_package || exit 1
echo "Packaging mod for Debian"
docker run --rm -t --name=mod_evasive_package -v `pwd`/dist:/opt/jvdmr/apache2/mod_evasive/dist mod_evasive_package bash debian-build.sh
echo "Done."
