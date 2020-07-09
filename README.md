# Accordably Server Log Analytics

Import your server logs in Accordably with this powerful and easy to use tool.

Build status (master branch) [![Build status](https://ci.appveyor.com/api/projects/status/ck2uarc6m724g6f7/branch/master?svg=true)](https://ci.appveyor.com/project/jayfk/logs/branch/master)

## Supported log formats


The script will import all standard web server log files, and some files with non-standard formats. The following log formats are supported:
 * all default log formats for: Nginx, Apache, IIS, Tomcat, Haproxy
 * all log formats commonly used such as: NCSA Common log format, Extended log format, W3C Extended log files, Nginx JSON, OVH
 * log files of some popular Cloud services: Amazon AWS CloudFront logs, AWS S3 logs, AWS ELB logs.
 * streaming media server log files such as: Icecast
 * log files with and without the virtual host will be imported

In general, many fields are left optional to make the log importer very flexible.

### Format Specific Details

* If you are importing Netscaler log files, make sure to specify the `--iis-time-taken-secs` option. Netscaler stores
  the time-taken field in seconds while most other formats use milliseconds. Using this option will ensure that the
  log importer interprets the field correctly.

* Some log formats can't be detected automatically as they would conflict with other formats. In order to import those logfiles make sure to specify the `--log-format-name` option.
  Those log formats are: OVH (ovh), Incapsula W3C (incapsula_w3c)

## How to import your logs automatically every day?

You must first make sure your logs are automatically rotated every day. The most
popular ways to implement this are using either:

* logrotate: http://www.linuxcommand.org/man_pages/logrotate8.html
  It will work with any HTTP daemon.
* rotatelogs: http://httpd.apache.org/docs/2.0/programs/rotatelogs.html
  Only works with Apache.
* let us know what else is useful and we will add it to the list

Your logs should be automatically rotated and stored on your webserver, for instance in daily logs
`/var/log/apache/access-%Y-%m-%d.log` (where %Y, %m and %d represent the year,
month and day).
You can then import your logs automatically each day (at 0:01). Setup a cron job with the command:

    1 0 * * * /path/to/matomo/misc/log-analytics/import-logs.py -u matomo.example.com `date --date=yesterday +/var/log/apache/access-\%Y-\%m-\%d.log`