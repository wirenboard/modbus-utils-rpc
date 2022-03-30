#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name="modbus-utils-rpc",
      version="1.0",
      author="Ekaterina Volkova",
      author_email="ekaterina.volkova@wirenboard.ru",
      description="Wiren Board modbus utility using RPC",
      url="https://github.com/wirenboard/modbus-utils-rpc",
      packages=find_packages(),
      license='MIT',
      entry_points={
          'console_scripts': [
              'modbus-utils-rpc = modbus_utils_rpc.main:main',
          ],
      }
      )
