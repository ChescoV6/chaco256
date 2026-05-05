#!/usr/bin/env python3
"""
Setup script for Chaco-256 Python package
"""

from setuptools import setup, find_packages
import os

# Read the README for long description
def read_file(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        return f.read()

setup(
    name='chaco256',
    version='1.0.0',
    author='Chaco-256 Project',
    author_email='contact@example.com',
    description='Chaco-256: High-Security Symmetric Encryption Algorithm',
    long_description=read_file('README.md'),
    long_description_content_type='text/markdown',
    url='https://github.com/example/chaco256',
    packages=find_packages(),
    py_modules=['chaco256'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Topic :: Security :: Cryptography',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.6',
    keywords='cryptography encryption cipher aead security',
    project_urls={
        'Bug Reports': 'https://github.com/example/chaco256/issues',
        'Source': 'https://github.com/example/chaco256',
        'Documentation': 'https://github.com/example/chaco256/blob/main/README.md',
    },
)
