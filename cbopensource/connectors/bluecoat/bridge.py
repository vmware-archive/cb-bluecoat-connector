from cbint.utils.detonation import DetonationDaemon, ConfigurationError
from cbint.utils.detonation.binary_analysis import (BinaryAnalysisProvider, AnalysisPermanentError,
                                                    AnalysisTemporaryError, AnalysisResult)
import cbint.utils.feed
import time
import logging
import os
import requests
import traceback
from time import sleep

logging.getLogger("requests").setLevel(logging.WARNING)

log = logging.getLogger(__name__)


class BluecoatProvider(BinaryAnalysisProvider):
    def __init__(self, name, bluecoat_url, bluecoat_api_key, bluecoat_owner):
        super(BluecoatProvider, self).__init__(name)

        # TODO -- pass in whether or not to verify ???

        self.bluecoat_url = bluecoat_url
        if not self.bluecoat_url.endswith('/'):
            self.bluecoat_url += "/"

        self.bluecoat_api_key = bluecoat_api_key
        self.bluecoat_owner = bluecoat_owner
        self.headers = {'X-API-TOKEN': self.bluecoat_api_key}

        self.sample_upload_url = "%srapi/samples/basic" % self.bluecoat_url
        self.create_task_url = "%srapi/tasks" % self.bluecoat_url

        self.check_url_format_str = "%srapi/samples?md5=%%s" % (self.bluecoat_url)
        self.get_tasks_url_format_str = "%srapi/samples/%%d/tasks" % self.bluecoat_url


    def check_result_for(self, md5sum, sample_id=None):

        try:

            if not sample_id:
                url = self.check_url_format_str % md5sum

                resp = requests.get(url, headers=self.headers, verify=False)
                sample_results = resp.json()
                result_count = sample_results.get('results_count', 0)
                if result_count == 0:
                    return None

                result = sample_results.get('results', [{}])[0]
                sample_id = result.get('samples_sample_id', -1)

            url = self.get_tasks_url_format_str % sample_id
            resp = requests.get(url, headers=self.headers, verify=False)
            log.warn("%s | %d" % (url, resp.status_code))

            tasks_results = resp.json()
            task_result = tasks_results.get('results', [{}])[0]
            task_id = task_result.get('tasks_task_id', -1)

            if not task_id: # do it over basically
                return None

            task_status = task_result.get('task_state_state', 'UNKNOWN')
            if task_status == 'CORE_COMPLETE':
                score = task_result['tasks_global_risk_score']

                task_link = "%sanalysis_center/view_task/%d" % (self.bluecoat_url, task_id)

                log.info("Binary %s score %d" % (md5sum, score))

                if score > 10:
                    malware_result = "Potential Malware"
                else:
                    malware_result = "Benign"

                return AnalysisResult(message=malware_result, extended_message="",
                                      link=task_link,
                                      score=score)
            else:
                raise AnalysisTemporaryError(message="No task result for %d (%d)" % (sample_id, task_id), retry_in=120)
        except:
            pass

    def analyze_binary(self, md5sum, binary_file_stream):
        try:
            description = 'Uploaded from Carbon Black'
            label = 'cb-%s' % md5sum

            sample_file = {'file': binary_file_stream}
            form_data = {'owner': self.bluecoat_owner, 'description': description, 'label': label}

            resp = requests.post(self.sample_upload_url, files=sample_file, data=form_data, headers=self.headers, verify=False)
            log.warn("%s | %d" % (self.sample_upload_url, resp.status_code))
            sample_upload_data = resp.json()
            sample_result = sample_upload_data.get('results', [{}])[0]

            # CREATE TASK
            sample_id = sample_result.get('samples_sample_id')
            task_data = {"sample_id":  sample_id, "env": "ivm"}
            resp = requests.post(self.create_task_url, data=task_data, headers=self.headers, verify=False)
            log.warn("%s | %d" % (self.create_task_url, resp.status_code))

            if resp.status_code != 200:
                raise AnalysisTemporaryError(message=resp.content, retry_in=120)

            retries = 10
            sleep_amount = 30
            while retries:
                sleep(sleep_amount)
                result = self.check_result_for(md5sum, sample_id=sample_id)
                if result:
                    return result
                retries -= 1

                # after the first time, sleep 15
                sleep_amount = 15

            raise AnalysisTemporaryError(message="Maximum retries (20) exceeded submitting to Cyphort", retry_in=120)

        except:
            traceback.print_exc()
            raise AnalysisTemporaryError(traceback.format_exc(), retry_in=120)



class BluecoatConnector(DetonationDaemon):
    @property
    def filter_spec(self):
        # TODO: finish

        # TODO -- DON'T HARDCODE THIS IN THE ACTUAL CODE

        filters = []
        max_module_len = 10 * 1024 * 1024

#        filters.append('(os_type:windows OR os_type:osx) orig_mod_len:[1 TO %d]' % max_module_len)
        filters.append('os_type:windows orig_mod_len:[1 TO %d]' % max_module_len)
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
        bluecoat_provider = BluecoatProvider(self.name, self.bluecoat_url, self.bluecoat_api_key, self.bluecoat_owner)
        return bluecoat_provider

    def get_metadata(self):
        # TODO: finish
        return cbint.utils.feed.generate_feed(self.name, summary="Bluecoat Malware Analysis Appliance Detonation",
                        tech_data="TECH DATA PLACEHOLDER",
                        provider_url="http://www.bluecoat.com",
                        icon_path='/usr/share/cb/integrations/bluecoat/bluecoat-logo.png',
                        display_name="Bluecoat", category="Connectors")

    def validate_config(self):
        super(BluecoatConnector, self).validate_config()
        self.check_required_options(["bluecoat_url", "bluecoat_api_key"])
        self.bluecoat_url = self.get_config_string("bluecoat_url", None)
        self.bluecoat_api_key = self.get_config_string("bluecoat_api_key", None)
        self.bluecoat_owner = self.get_config_string("bluecoat_owner", "admin")

        return True


if __name__ == '__main__':
    import os

    my_path = os.path.dirname(os.path.abspath(__file__))
    temp_directory = "/tmp/bluecoat"

    config_path = os.path.join(my_path, "testing.conf")
    daemon = BluecoatConnector('bluecoattest', configfile=config_path, work_directory=temp_directory,
                                logfile=os.path.join(temp_directory, 'test.log'), debug=True)
    daemon.start()