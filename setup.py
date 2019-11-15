#!/usr/bin/env python

from setuptools import setup

tests_require = ['pytest']

setup(
    name='werkzeug-encryptedcookie',
    version='3.0',
    url='https://github.com/homm/werkzeug-encryptedcookie',
    author='Alexander Karpinsky',
    author_email='homm86@gmail.com',
    description='Werkzeug encrypted cookie',
    packages=['werkzeug_encryptedcookie'],
    platforms='any',
    install_requires=['PyCrypto>=2.5', 'werkzeug'],
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
    tests_require=tests_require,
    test_suite='test',
)
