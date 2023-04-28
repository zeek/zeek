#!/bin/sh

zypper refresh
zypper patch -y --with-update --with-optional
