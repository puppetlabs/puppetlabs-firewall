## puppetlabs-firewall module

### Overview

This is the puppet-firewall module. Here we are providing a module which can be used to configure various firewalls

### Disclaimer

Warning! While this software is written in the best interest of quality it has not been formally tested by our QA teams. Use at your own risk, but feel free to enjoy and perhaps improve it while you do.

Please see the included Apache Software License for more legal details regarding warranty.

### Installation

From github, download the module into your modulepath on your Puppetmaster. If you are not sure where your module path is try this command:

    puppet --configprint modulepath

Depending on the version of Puppet, you may need to restart the puppetmasterd (or Apache) process before this module will work.

### Quickstart

Once the module is in the correct modulepath, you should be able to create some
firewall rules like the below examples. Remember, that rules are lexically 
ordered by the resource title at this point.

Basic accept ICMP request example:

    firewall { "000 accept all icmp requests":
      proto => "icmp",
      jump => "ACCEPT",
    }

Deny all:

    firewall { "999 deny all other requests":
      jump => "DENY",
    }

### Supported firewalls

Currently we support:

* Iptables

But plans are to support lots of other firewall implementations:

* Linux IPv6 (ip6tables)
* FreeBSD (ipf)
* Mac OS X (ipfw)
* OpenBSD (pf)
* Cisco (ASA and basic access lists)

If you have knowledge in these rules and wish to contribute to this project
feel free to submit patches (after signing a Puppetlabs CLA :-).
