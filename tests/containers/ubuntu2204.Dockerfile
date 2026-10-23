# Ubuntu 22.04 with PHP 8.1 (an end-of-life branch upstream) from the release pocket.
# An apt pin blocks the PHP packages of jammy-security and jammy-updates during the install
# only. Ubuntu backports security fixes without changing the upstream version, so this
# target tests the changelog check and the EOL path. The pin is removed afterwards.
ARG BASE=ubuntu:22.04
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN printf '#!/bin/sh\nexit 101\n' >/usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d \
 && printf 'Package: php* libapache2-mod-php* libphp*\nPin: release a=jammy-security\nPin-Priority: -1\n\nPackage: php* libapache2-mod-php* libphp*\nPin: release a=jammy-updates\nPin-Priority: -1\n' \
      >/etc/apt/preferences.d/php-safepatch-test-hold \
 && apt-get update -qq \
 && apt-get install -y -q --no-install-recommends \
      php8.1-cli php8.1-fpm php8.1-mbstring libapache2-mod-php8.1 apache2 curl ca-certificates procps \
 && rm -f /etc/apt/preferences.d/php-safepatch-test-hold \
 && rm -rf /var/lib/apt/lists/*
LABEL php-safepatch.family=debian php-safepatch.branch=8.1
