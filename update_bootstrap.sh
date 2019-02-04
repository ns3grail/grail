#!/bin/sh
set -e
set -u
git archive --format=tar.gz HEAD > docker/bootstrap.tar.gz
