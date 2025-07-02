#!/usr/bin/env python

from setuptools import setup


setup(
    name='encryptedcookie',
    version='1.1',
    url='https://github.com/uploadcare/encryptedcookie',
    author='Uploadcare',
    author_email='ak@uploadcare.com',
    description='encrypted cookie',
    packages=['encryptedcookie'],
    platforms='any',
    install_requires=['pycryptodome>=3.11.0', 'brotli>=1.0.1'],
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    extras_require={
        'test': ['pytest>=8.3.2', 'pytest-cov>=5.0.0'],
        'lint': ['isort', 'flake8', 'pyright'],
    },
    test_suite='test',
)
