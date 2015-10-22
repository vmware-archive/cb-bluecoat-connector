# Carbon Black - Bluecoat Connector

## Installation Quickstart

As root on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-bluecoat-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/bluecoat/connector.conf.example` file to
`/etc/cb/integrations/bluecoat/connector.conf`. Edit this file and place your Carbon Black API key into the
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

You'll also need to update the settings for `bluecoat_url`, `bluecoat_api_key`, and `bluecoat_owner` (your bluecoat username).

Optionally, you can update the `binary_filter_query` setting if you want to exclude more binaries.  This query is what gets passed to the Carbon Black Binary Search page to find new binaries so you can test your queries there first if you want to make modifications away from default.  By default, we submit binaries that are 32-bit and not published by Microsoft Corporation.

Once the configuration file has been renamed and the settings updated, you can start the service with the following command:

`service cb-bluecoat-connector start`

All log messages (and errors) will be logged into `/var/log/cb/integrations/bluecoat/bluecoat.log`.

## Troubleshooting

If you suspect a problem, please first look at the Bluecoat connector logs found here:
`/var/log/cb/integrations/bluecoat/bluecoat.log`
(There might be multiple files as the logger "rolls over" when the log file hits a certain size).

If you want to re-run the analysis across your binaries:
1. Stop the service: `service cb-bluecoat-connector stop`
2. Remove the database file: `rm /usr/share/cb/integrations/bluecoat/db/sqlite.db`
3. Remove the feed from your Cb server's Threat Intelligence page
4. Restart the service: `service cb-bluecoat-connector start`

## Contacting Bit9 Developer Relations Support

Web: https://community.bit9.com/groups/developer-relations
E-mail: dev-support@bit9.com

### Reporting Problems

When you contact Bit9 Developer Relations Technical Support with an issue, please provide the following:

* Your name, company name, telephone number, and e-mail address
* Product name/version, CB Server version, CB Sensor version
* Hardware configuration of the Carbon Black Server or computer (processor, memory, and RAM)
* For documentation issues, specify the version of the manual you are using.
* Action causing the problem, error message returned, and event log output (as appropriate)
* Problem severity
