## puppetlabs-firewall changelog

Release notes for puppetlabs-firewall module.

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
