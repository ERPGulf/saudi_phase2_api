# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

with open('requirements.txt') as f:
        install_requires = f.read().strip().split('\n')

# get version from __version__ variable in axis_inspection/__init__.py
from axis_inspection import __version__ as version

setup(
        name='Saudi Phase2 Api',
        version=version,
        description='Saudi Phase2 Api',
        author='HusnaM',
        author_email='support@erpgulf.com',
        packages=find_packages(),
        zip_safe=False,
        include_package_data=True,
        install_requires=install_requires
)
