FROM jvdmr/apache-dev:latest AS build
MAINTAINER @jvdmr

ADD . /opt/jvdmr/apache2/mod_evasive
WORKDIR /opt/jvdmr/apache2/mod_evasive

RUN mv mod_evasive24.c mod_evasive.c && \
    /usr/bin/apxs -i -a -c -l pcre2-8 mod_evasive.c && \
		apache2ctl configtest

CMD bash


FROM debian:stable AS test

EXPOSE 80

WORKDIR /opt/jvdmr/apache2/mod_evasive

ARG test_path test/00_regular_config

RUN apt-get update
RUN apt-get -y install apache2

COPY --from=build /usr/lib/apache2/modules/mod_evasive.so /usr/lib/apache2/modules/mod_evasive.so
COPY --from=build /etc/apache2/mods-available/evasive.load /etc/apache2/mods-available/evasive.load

RUN mkdir -p /opt/jvdmr/apache2/mod_evasive
COPY ${test_path}/www /opt/jvdmr/apache2/mod_evasive/www
COPY ${test_path}/etc/mod_evasive.conf /etc/apache2/conf-enabled/mod_evasive.conf
COPY ${test_path}/etc/sites.conf /etc/apache2/sites-enabled/sites.conf

RUN a2enmod evasive
CMD service apache2 start && bash


FROM jvdmr/apache-dev:latest AS package

WORKDIR /opt/jvdmr/apache2/mod_evasive

COPY --from=build /usr/lib/apache2/modules/mod_evasive.so /usr/lib/apache2/modules/mod_evasive.so
COPY mod_evasive.conf /etc/apache2/conf-enabled/mod_evasive.conf
COPY debian-build.sh debian-build.sh

CMD bash
