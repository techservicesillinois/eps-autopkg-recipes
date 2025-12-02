#!/usr/local/autopkg/python
#
# Copyright 2020 Drew Coobs
# WARNING: This is an independent project and is not supported by CrowdStrike.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import ssl
import sys
import urllib.error
from urllib import parse, request

import autopkglib.github
from autopkglib import Processor, ProcessorError

__all__ = ["CrowdStrikeDownloadAPIProvider"]


class CrowdStrikeDownloadAPIProvider(Processor):
    description = (
        "Downloads the latest version of the CrowdStrike sensor"
        "WARNING: This is an independent project and is not supported by CrowdStrike."
    )
    input_variables = {
        "client_id": {
            "required": True,
            "description": (
                "CrowdStrike API Client ID"
            ),
        },
        "client_secret": {
            "required": True,
            "description": (
                "CrowdStrike API Secret"
            ),
        },
        "output_file": {
            "required": True,
            "description": (
                "Name of output file"
            ),
        },
        "platform": {
            "required": False,
            "default": 'mac',
            "description": (
                "Optional string to set the OS platform to download the latest sensor for."
                "Options: 'mac', 'windows', or 'linux'"
                "Defaults to 'mac'"
            ),
        },
        "cloud": {
            "required": False,
            "default": 'US',
            "description": (
                "Optional string to set the cloud to send commands to."
                "Options: 'US', 'US-2', 'EU', or 'USFed'"
                "Defaults to 'US'"
            ),
        },
    }
    output_variables = {
        "pathname": {
            "description": ("Path to the downloaded sensor installer")
        },
        "version": {
            "description": (
                "Version info parsed from the API json metadata"
            )
        },
    }

    __doc__ = description

    def cloudurl(self, cloud):
        switcher ={
             'US':'api.crowdstrike.com',
             'US-2':'api.us-2.crowdstrike.com',
             'USFed':'api.laggar.gcw.crowdstrike.com',
             'EU':'api.eu-1.crowdstrike.com'
        }
        return switcher.get(cloud, 'api.crowdstrike.com')

    def urlopen_func(self, req):
        try:
            # Disable default SSL validation for urllib
            ssl._create_default_https_context = ssl._create_unverified_context
            urlopen_response = request.urlopen(req)
            return urlopen_response
        except urllib.error.HTTPError as err:
            raise ProcessorError(f"HTTP error making API call!")
            self.output(err)
            error_json = err.read()
            error = json.loads(error_json)
            self.output(f"API message: {error['errors'][0]['message']}")
            sys.exit(1)

    def main(self):
        cloudapiurl = self.cloudurl(self.env["cloud"])

        ### API URLs ###
        auth_token_api_url = 'https://{}/oauth2/token'.format(cloudapiurl)
        sensor_hash_api_url = "https://{}/sensors/combined/installers/v1?offset=0&limit=1&filter=platform%3A%22{}%22".format(cloudapiurl,self.env["platform"])
        sensor_download_api_url = "https://{}/sensors/entities/download-installer/v1?id={}"

        ### Obtain API auth token ###
        token_headers = {
            'accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        token_data = {
            'client_id': self.env["client_id"],
            'client_secret': self.env["client_secret"]
        }
        token_data = parse.urlencode(token_data)
        token_data = token_data.encode('ascii')
        req = request.Request(auth_token_api_url, headers=token_headers, data=token_data)
        response = self.urlopen_func(req)
        token_parsed = json.loads(response.read())
        auth_token = token_parsed['access_token']

        ### Obtain installer hash for latest sensor ###
        sensor_hash_headers = {
            'accept': 'application/json',
            'authorization': "bearer {}".format(auth_token),
            'Content-Type': 'application/json',
        }
        req = request.Request(sensor_hash_api_url, headers=sensor_hash_headers)
        response = self.urlopen_func(req)
        sensor_hash_parsed = json.loads(response.read())
        sensor_hash_name = sensor_hash_parsed['resources'][0]['name']
        sensor_hash_version = sensor_hash_parsed['resources'][0]['version']
        sensor_hash_sha256 = sensor_hash_parsed['resources'][0]['sha256']
        self.env["version"] = sensor_hash_version

        ### Download the latest sensor ###
        self.output("Downloading %s" % sensor_hash_name)
        self.output("Version: %s" % self.env["version"])
        download_headers = {
            'accept': 'application/json',
            'authorization': "bearer {}".format(auth_token),
            'Content-Type': 'application/json',
        }

        sensor_download_url = sensor_download_api_url.format(cloudapiurl,sensor_hash_sha256)
        req = request.Request(sensor_download_url, headers=download_headers)
        response = self.urlopen_func(req)
        with open(self.env["output_file"], 'wb') as file:
            file.write(response.read())
        self.env["pathname"] = self.env["output_file"]

if __name__ == "__main__":
    PROCESSOR = GitHubReleasesInfoProvider()
    PROCESSOR.execute_shell()
