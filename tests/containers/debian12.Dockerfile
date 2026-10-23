# Debian 12 with PHP 8.2 from the release pocket. An apt pin blocks the PHP packages of
# bookworm-security during the install only, so the installed PHP is older than the
# security fix while the rest of the system stays current. The pin is removed afterwards,
# so php-safepatch sees the security update as an unpatched server does.
ARG BASE=debian:12
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d \
 && printf 'Package: php* libapache2-mod-php* libphp*\nPin: release l=Debian-Security\nPin-Priority: -1\n' \
      >/etc/apt/preferences.d/php-safepatch-test-hold \
 && apt-get update -qq \
 && apt-get install -y -q --no-install-recommends \
      php8.2-cli php8.2-fpm php8.2-mbstring libapache2-mod-php8.2 apache2 curl ca-certificates procps \
 && rm -f /etc/apt/preferences.d/php-safepatch-test-hold \
 && rm -rf /var/lib/apt/lists/*
LABEL php-safepatch.family=debian php-safepatch.branch=8.2
