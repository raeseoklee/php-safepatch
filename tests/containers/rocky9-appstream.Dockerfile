# Rocky Linux 9 with the AppStream "php:8.2" module stream.
# The module stream keeps the branch fixed, so dnf must not move PHP to another branch.
ARG BASE=rockylinux/rockylinux:9
FROM ${BASE}
RUN dnf -y -q module reset php \
 && dnf -y -q module enable php:8.2 \
 && dnf -y -q install php-cli php-fpm php-mbstring httpd procps-ng findutils \
 && dnf clean all
LABEL php-safepatch.family=rhel php-safepatch.branch=8.2
