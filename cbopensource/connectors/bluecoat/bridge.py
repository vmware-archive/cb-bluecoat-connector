from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult)
import cbint.utils.feed
import time
import logging
import os


log = logging.getLogger(__name__)


class BluecoatProvider(BinaryAnalysisProvider):
    def __init__(self, name, bluecoat_url, bluecoat_api_key):
        super(BluecoatProvider, self).__init__(name)
        self.bluecoat_url = bluecoat_url
        self.bluecoat_api_key = bluecoat_api_key
        self.headers = {'X-API-TOKEN': self.bluecoat_api_key}

    def check_result_for(self, md5sum):
        # TODO: finish
        return None

    def analyze_binary(self, md5sum, binary_file_stream):
        # TODO: finish
        pass


class BluecoatConnector(DetonationDaemon):
    @property
    def filter_spec(self):
        # TODO: finish

        filters = []
        max_module_len = 10 * 1024 * 1024

        filters.append('(os_type:windows OR os_type:osx) orig_mod_len:[1 TO %d]' % max_module_len)
        additional_filter_requirements = self.get_config_string("binary_filter_query", None)
        if additional_filter_requirements:
            filters.append(additional_filter_requirements)

        return ' '.join(filters)

    @property
    def num_quick_scan_threads(self):
        return 0

    @property
    def num_deep_scan_threads(self):
        return 4

    def get_provider(self):
        bluecoat_provider = BluecoatProvider(self.name, self.bluecoat_url, self.bluecoat_api_key)
        return bluecoat_provider

    def get_metadata(self):
        # TODO: finish
        return cbint.utils.feed.generate_feed(self.name, summary="SUMMARY PLACEHOLDER",
                        tech_data="TECH DATA PLACEHOLDER",
                        provider_url="http://www.bluecoat.com",
                        icon_path='/usr/share/cb/integrations/bluecoat/bluecoat-logo.png',
                        display_name="Bluecoat", category="Connectors")

    def validate_config(self):
        super(BluecoatConnector, self).validate_config()
        self.check_required_options(["bluecoat_url", "bluecoat_api_key"])
        self.bluecoat_url = self.get_config_string("bluecoat_url", None)
        self.bluecoat_api_key = self.get_config_string("bluecoat_api_key", None)

        return True


if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/bluecoat"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = BluecoatConnector('bluecoattest', configfile=config_path, work_directory=temp_directory,
                                logfile=os.path.join(temp_directory, 'test.log'), debug=True)
    daemon.start()