## puppetlabs-firewall changelog

Release notes for puppetlabs-firewall module.

---------------------------------------

#### 0.0.4 - 2011/12/05

This release adds two new parameters, 'uid' and 'gid'. As a part of the owner module, these params allow you to specify a uid, username, gid, or group got a match:

    firewall { '497 match uid':
      port => '123',
      proto => 'mangle',
      chain => 'OUTPUT',
      action => 'drop'
      uid => '123'
    }

This release also adds value munging for the 'log_level', 'source', and 'destination' parameters. The 'source' and 'destination' now support hostnames:

    firewall { '498 accept from puppetlabs.com':
      port => '123',
      proto => 'tcp',
      source => 'puppetlabs.com',
      action => 'accept'
    }


The 'log_level' parameter now supports using log level names, such as 'warn', 'debug', and 'panic':

    firewall { '499 logging':
      port => '123',
      proto => 'udp',
      log_level => 'debug',
      action => 'drop'
    }

Additional changes include iptables and ip6tables version facts, general whitespace cleanup, and adding additional unit tests.

##### Changes

* (#10957) add iptables_version and ip6tables_version facts
* (#11093) Improve log_level property so it converts names to numbers
* (#10723) Munge hostnames and IPs to IPs with CIDR
* (#10718) Add owner-match support
* (#10997) Add fixtures for ipencap
* (#11034) Whitespace cleanup
* (#10690) add port property support to ip6tables

---------------------------------------

#### 0.0.3 - 2011/11/12

This release introduces a new parameter 'port' which allows you to set both
source and destination ports for a match:

    firewall { "500 allow NTP requests":
      port => "123",
      proto => "udp",
      action => "accept",
    }

We also have the limit parameter finally working:

    firewall { "500 limit HTTP requests":
      dport => 80,
      proto => tcp,
      limit => "60/sec",
      burst => 30,
      action => accept,
    }

State ordering has been fixed now, and more characters are allowed in the
namevar:

* Alphabetical
* Numbers
* Punctuation
* Whitespace

##### Changes

* (#10693) Ensure -m limit is added for iptables when using 'limit' param
* (#10690) Create new port property
* (#10700) allow additional characters in comment string
* (#9082) Sort iptables --state option values internally to keep it consistent across runs
* (#10324) Remove extraneous whitespace from iptables rule line in spec tests

---------------------------------------

#### 0.0.2 - 2011/10/26

This is largely a maintanence and cleanup release, but includes the ability to
specify ranges of ports in the sport/dport parameter:

    firewall { "500 allow port range":
      dport => ["3000-3030","5000-5050"],
      sport => ["1024-65535"],
      action => "accept",
    }

##### Changes

* (#10295) Work around bug #4248 whereby the puppet/util paths are not being loaded correctly on the puppetmaster
* (#10002) Change to dport and sport to handle ranges, and fix handling of name to name to port
* (#10263) Fix tests on Puppet 2.6.x
* (#10163) Cleanup some of the inline documentation and README file to align with general forge usage

---------------------------------------

#### 0.0.1 - 2011/10/18

Initial release.

##### Changes

* (#9362) Create action property and perform transformation for accept, drop, reject value for iptables jump parameter
* (#10088) Provide a customised version of CONTRIBUTING.md
* (#10026) Re-arrange provider and type spec files to align with Puppet
* (#10026) Add aliases for test,specs,tests to Rakefile and provide -T as default
* (#9439) fix parsing and deleting existing rules
* (#9583) Fix provider detection for gentoo and unsupported linuxes for the iptables provider
* (#9576) Stub provider so it works properly outside of Linux
* (#9576) Align spec framework with Puppet core
* and lots of other earlier development tasks ...
