# Carbon Black - Bluecoat Connector

## Legacy/Deprecated

Future versions of Bluecoat MAA will not be supported.  This connector is now in legacy/deprecated status and will no longer
be maintained.

## Installation Quickstart

As **root** on your Carbon Black or other RPM based 64-bit Linux distribution server:
```
cd /etc/yum.repos.d
curl -O https://opensource.carbonblack.com/release/x86_64/CbOpenSource.repo
yum install python-cb-bluecoat-connector
```

Once the software is installed via YUM, copy the `/etc/cb/integrations/bluecoat/connector.conf.example` file to
`/etc/cb/integrations/bluecoat/connector.conf`. Edit this file and place your Carbon Black API key into the
`carbonblack_server_token` variable and your Carbon Black server's base URL into the `carbonblack_server_url` variable.

You'll also need to update the settings for `bluecoat_url` (address of your Bluecoat MAA device), `bluecoat_api_key` (your Bluecoat MAA API key), and `bluecoat_owner` (most likely your Bluecoat MAA username).

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

## Support

1. Use the [Developer Community Forum](https://community.carbonblack.com/t5/Developer-Relations/bd-p/developer-relations) to discuss issues and ideas with other API developers in the Carbon Black Community.
2. Report bugs and change requests through the GitHub issue tracker. Click on the + sign menu on the upper right of the screen and select New issue. You can also go to the Issues menu across the top of the page and click on New issue.
3. View all API and integration offerings on the [Developer Network](https://developer.carbonblack.com/) along with reference documentation, video tutorials, and how-to guides.
