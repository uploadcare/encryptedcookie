#!/usr/bin/env python

from setuptools import setup


setup(
    name='werkzeug-encryptedcookie',
    version='4.0',
    url='https://github.com/homm/werkzeug-encryptedcookie',
    author='Alexander Karpinsky',
    author_email='homm86@gmail.com',
    description='Werkzeug encrypted cookie',
    packages=['werkzeug_encryptedcookie'],
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
        'test': ['pytest'],
        'lint': ['isort', 'flake8', 'pyright'],
    },
    test_suite='test',
)
