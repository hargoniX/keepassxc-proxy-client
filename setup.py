#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

from keepassxc_proxy_client import __version__


# Build the page that will be displayed on PyPI from the README and CHANGELOG
with open("README.md", encoding="utf-8") as f:
    long_description = f.read()
long_description += "\n\n"
with open("CHANGELOG.md", encoding="utf-8") as f:
    long_description += f.read()
with open('requirements.txt') as f:
    required = f.read().splitlines()


setup(
    name="keepassxc-proxy-client",
    version=__version__,
    author="Henrik Boeving",
    author_email="hargonix@gmail.com",
    description="A CLI for keepassxc-proxy",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hargoniX/keepassxc-proxy-client",
    project_urls={
        "Issue tracker": "https://github.com/hargoniX/keepassxc-proxy-client/issues",
        "Changelog": "https://github.com/hargoniX/keepassxc-proxy-client/blob/master/CHANGELOG.md",
    },
    packages=["keepassxc_proxy_client"],
    zip_safe=True,
    entry_points={"console_scripts": ["keepassxc_proxy_client = keepassxc_proxy_client.__main__:main"]},
    install_requires=required,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Libraries",
        "Topic :: System :: Systems Administration",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
    ],
)
