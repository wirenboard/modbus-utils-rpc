#!/usr/bin/env python

from setuptools import setup


def get_version():
    with open("debian/changelog", "r", encoding="utf-8") as f:
        return f.readline().split()[1][1:-1]


setup(
    name="modbus-utils-rpc",
    version=get_version(),
    author="Ekaterina Volkova",
    author_email="ekaterina.volkova@wirenboard.ru",
    maintainer="Wiren Board Team",
    maintainer_email="info@wirenboard.com",
    description="Wiren Board modbus utility using RPC",
    url="https://github.com/wirenboard/modbus-utils-rpc",
    packages=["modbus_client_rpc", "modbus_scanner_rpc"],
    license="MIT",
)
