#!/usr/bin/env python

import os

from setuptools import setup


def readreq(filename):
    result = []
    with open(filename) as f:
        for req in f:
            req = req.lstrip()
            if req.startswith('-e ') or req.startswith('http:'):
                idx = req.find('#egg=')
                if idx >= 0:
                    req = req[idx + 5:].partition('#')[0].strip()
                else:
                    pass
            else:
                req = req.partition('#')[0].strip()
            if not req:
                continue
            result.append(req)
    return result


def readfile(filename):
    with open(filename) as f:
        return f.read()


setup(
    name='policies',
    version='0.2.2',
    author='Kevin L. Mitchell',
    author_email='klmitch@mit.edu',
    url='https://github.com/klmitch/policies',
    description="An access policy language evaluator.",
    long_description=readfile('README.rst'),
    license='GNU General Public License v3 or later (GPLv3+)',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 '
            'or later (GPLv3+)',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Software Development :: Interpreters',
        'Topic :: Software Development :: Libraries',
    ],
    packages=['policies'],
    install_requires=readreq('requirements.txt'),
    tests_require=readreq('test-requirements.txt'),
)
