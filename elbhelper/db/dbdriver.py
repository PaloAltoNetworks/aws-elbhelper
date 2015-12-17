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

__author__ = 'ivanbojer'
__version__ = ''

import ConfigParser
import logging

from boto.s3.connection import S3Connection, S3ResponseError
from boto.s3.key import Key

from elbhelper.config import defaults as CFG

LOG = logging.getLogger(__name__)

class FileDB(object):
    """
    This class represents a poor man database that stores data in the property-like file.
    It should be used as the last resort.
    """
    TABLE_ASSIGNEMENTS='assignements'
    TABLE_MAPPING='mappings'

    def __init__(self, cfg_file):
        logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y%m%d %T', level=logging.DEBUG)
        self.ha = CFG.S3_HA

        if self.ha:
            conn = S3Connection(profile_name=CFG.S3_CREDENTIALS_PROFILE)
            bucket = conn.get_bucket(CFG.S3_BUCKET)
            self.k = Key(bucket)
            self.k.key = CFG.DB_FILE

        self.__initialize_db_file()

        self.cfg_file = cfg_file
        self.__configDB = ConfigParser.ConfigParser()
        self.load_db()

    def add_address(self, address, fw_addr):
        self.db_file.set(self.TABLE_MAPPING, address, fw_addr)
        self.save_db()

    def del_address(self, address):
        self.db_file.remove_option(self.TABLE_MAPPING, address)
        self.save_db()

    def add_assignement(self, fw_adr, elb_adr):
        self.db_file.set(self.TABLE_ASSIGNEMENTS, fw_adr, elb_adr)
        self.save_db()

    def del_assignement(self, fw_adr):
        self.db_file.remove_option(self.TABLE_ASSIGNEMENTS, fw_adr)
        self.save_db()

    def clear_assignements(self):
        self.db_file.remove_section(self.TABLE_ASSIGNEMENTS)
        self.db_file.add_section(self.TABLE_ASSIGNEMENTS)
        self.save_db()

    def get_elb_addrs(self):
        elb_addrs_tuples = self.db_file.items(self.TABLE_MAPPING)

        return dict(elb_addrs_tuples).keys()

    def get_assigned_fw(self, elb_addr):
        firewalls = dict(self.db_file.items(self.TABLE_ASSIGNEMENTS))

        for fw in firewalls:
            if elb_addr in firewalls[fw]:
                return fw

        return None

    def get_assigned_addresses(self, fw_addr=None):
        assigned_addr_tuples = dict(self.db_file.items(self.TABLE_ASSIGNEMENTS))
        assigned_addr = []
        if fw_addr is None:
            assigned_addr = assigned_addr_tuples.values()
        else:
            try:
                assigned_addr = assigned_addr_tuples[fw_addr]
            except KeyError:
                # swallow
                assigned_addr = []

        return assigned_addr

    def is_fw_occupied(self, fw_addr):
        assigned_addr = self.get_assigned_addresses(fw_addr)

        return len(assigned_addr) > 0

    def save_db(self):
        with open(self.cfg_file, 'wb') as configfile:
            self.db_file.write(configfile)
        configfile.close()

        if (self.ha):
            with open(self.cfg_file, 'r') as myfile:
                data=myfile.read()
            myfile.close()
            self.k.set_contents_from_string(data)

    def load_db(self):
        if (self.ha):
            self.k.get_contents_to_filename(CFG.DB_FILE)
        self.db_file.read(self.cfg_file)

    def __initialize_db_file(self):
        """This is called only once at the beginning. If HA is enabled it tries to
        download a file from the S3 bucket. If it cannot find one it will attempt
        to initialize an empty db file and upload it to the S3"""

        # if we do not need HA bail out
        if not self.ha:
            return

        try:
            self.k.get_acl()
        except S3ResponseError as ex:
            if ex.status == 404:
                LOG.warn('Database file %s not found in S3 bucket [%s]. Initializing the new one',
                         CFG.DB_FILE, CFG.S3_BUCKET)
                self.k.set_contents_from_string('[mappings]\n[assignements]\n')
            else:
                LOG.fatal('There was a communication issue with S3 bucket [%s] accessing the file %s. Exception: %s',
                          ex, CFG.S3_BUCKET, CFG.DB_FILE, ex)
                import sys
                sys.exit(0)


    @property
    def db_file(self):
        """
        Return the property once we are assured that we have the latest version.
        Given that the HA is done as add-hoc and that we do not have the real database
        the only way to achieve this (and it is not bullet proof) is to download the file
        every time someone is accessing it. This is ugly and bad.
        """
        return self.__configDB

    def get_inverse_idx(self):
        """given that we dont use real database this will build us our inverse index"""
        addresses = self.db_file.items(self.TABLE_MAPPING)

        fw_reverse_idx = dict()

        for adr in addresses:
            if adr[1] in fw_reverse_idx:
                fw_reverse_idx[adr[1]].append(adr[0])
            else:
                fw_reverse_idx[adr[1]] = [adr[0]]

        return fw_reverse_idx


class SQLiteDB(object):
    """
    SQLLite DB
    """
    def __init__(self):
        raise NotImplemented('SQLiteDB adapter not implemented')
