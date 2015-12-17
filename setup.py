#  Copyright 2015 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from setuptools import setup, find_packages

import sys
import os.path
sys.path.insert(0, os.path.abspath('.'))

from elbhelper import __version__

with open('requirements.txt') as f:
    _requirements = f.read().splitlines()

with open('README.md') as f:
    _long_description = f.read()

setup(
    name='elbhelper',
    version=__version__,
    packages=find_packages(),
    url='https://github.com/PaloAltoNetworks-BD/aws-elbhelper',
    license='http://www.apache.org/licenses/LICENSE-2.0',
    author='ivanbojer',
    author_email='techbizdev@paloaltonetworks.com',
    description='Targeted script that allows update of the FW NAT rules based on the dynamic AWS ELB VIP changes',
    include_package_data=True,
    install_requires=_requirements
)
