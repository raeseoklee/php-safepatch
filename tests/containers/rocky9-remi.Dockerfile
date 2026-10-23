# Rocky Linux 9 with PHP 8.2 from the Remi "php:remi-8.2" module stream.
# Remi also offers 8.3, 8.4 and 8.5 streams, so this target checks that apply stays on 8.2
# while newer branches are available in the same repository.
ARG BASE=rockylinux/rockylinux:9
FROM ${BASE}
RUN dnf -y -q install epel-release \
 && dnf -y -q install https://rpms.remirepo.net/enterprise/remi-release-9.rpm \
 && dnf -y -q module reset php \
 && dnf -y -q module enable php:remi-8.2 \
 && dnf -y -q install php-cli php-fpm php-mbstring httpd procps-ng findutils \
 && dnf clean all
LABEL php-safepatch.family=rhel php-safepatch.branch=8.2
