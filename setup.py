"""
   Copyright 2018 CAPITAL LAB OU

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import os
import re
import sys

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path

PACKAGES = ['apilityio', 'tests']

DEPENDENCIES = ['requests>=2.0.0,<3.0.0', 'validators>=0.12.2,<1.0.0']

# Note: Breaking change introduced in pyfakefs 3.3.
TEST_DEPENDENCIES = ['mock>=2.0.0,<3.0.0', 'pyfakefs>=3.2,<3.3',
                     'six>=1.11.0,<2.0.0', 'validators>=0.12.2,<1.0.0']

CLASSIFIERS = [
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'Intended Audience :: Science/Research',
    'License :: OSI Approved :: Apache Software License',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
    'Topic :: Security',
    'Topic :: Software Development :: Libraries :: Python Modules'
]

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

def GetVersion():
  """Gets the version from apilityio/common.py.

  We can't import this directly because new users would get ImportErrors on our
  third party dependencies.

  Returns:
    The version of the library.
  """
  with open(os.path.join('apilityio', 'common.py')) as versions_file:
    source = versions_file.read()
  return re.search('\\nVERSION = \'(.*?)\'', source).group(1)


extra_params = {}
if sys.version_info[0] == 3:
  extra_params['use_2to3'] = True

setup(name='apilityio-lib',
      version=GetVersion(),
      description='Apility.io Python Client Library',
      author='Apility.io Devops Team',
      author_email='devops@apility.io',
      url='https://github.com/Apilityio/python-lib',
      license='Apache License 2.0',
      long_description=long_description,
      packages=PACKAGES,
      platforms='any',
      keywords='apilityio apility abuse malicious',
      classifiers=CLASSIFIERS,
      install_requires=DEPENDENCIES,
      tests_require=TEST_DEPENDENCIES,
      test_suite='tests',
      **extra_params)
