__author__ = 'jmcfarland'

import unittest
from ConfigParser import SafeConfigParser
import os
from hashlib import md5

from cbopensource.connectors.bluecoat.bridge import BluecoatProvider
from cbopensource.connectors.bluecoat import bridge


class BluecoatTest(unittest.TestCase):
    def setUp(self):
        bridge_file = bridge.__file__
        config_path = os.path.join(os.path.dirname(os.path.abspath(bridge_file)), "testing.conf")

        self.test_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "randdata")

        self.config = SafeConfigParser()
        self.config.read(config_path)

        self.bluecoat_provider = BluecoatProvider('bluecoat-test', 
            self.config.get("bridge", "bluecoat_url"),
            self.config.get("bridge", "bluecoat_api_key"), 
            self.config.get("bridge", "bluecoat_owner"))

    def test_submit_md5sum(self):
        #
        # NOTE: use a hash of something we have already submitted
        # Depending on the BlueCoat MAA you are using you might have to change this hash
        #
        print self.bluecoat_provider.check_result_for('2c00c4d5a3aa8f6e7bb4cf0b658ee2e0')

    def test_submit_binary(self):
        with open(self.test_file, 'wb+') as hfile:
            hfile.write(os.urandom(1024))
            hfile.seek(0)
            self.md5sum_test_file = md5(hfile.read()).hexdigest()
            hfile.seek(0)
            print self.bluecoat_provider.analyze_binary(self.md5sum_test_file, hfile)

        #
        # Delete the test file
        #
        os.remove(self.test_file)

    def test_submitted_binary(self):
        with open(self.test_file, 'wb+') as hfile:
            hfile.write(os.urandom(1024))
            hfile.seek(0)
            self.md5sum_test_file = md5(hfile.read()).hexdigest()
            hfile.seek(0)
            #
            # Unit tests should not be dependent on each other
            #
            self.bluecoat_provider.analyze_binary(self.md5sum_test_file, hfile)

            #
            # Now do a seperate check_result_for to make sure that is tested
            #
            print self.bluecoat_provider.check_result_for(self.md5sum_test_file)

        #
        # Delete the test file
        #
        os.remove(self.test_file)
