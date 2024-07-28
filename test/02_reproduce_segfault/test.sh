#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
${DIR}/test.pl
docker exec -it mod_evasive_test service apache2 graceful
sleep 5
${DIR}/test.pl
