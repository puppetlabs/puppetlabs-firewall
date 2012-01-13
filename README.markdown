## puppetlabs-firewall module

## User Guide

### Overview

This type provides the capability to manage firewall rules within 
puppet.

Current support includes:

* iptables
* ip6tables

### Disclaimer

Warning! While this software is written in the best interest of quality it has
not been formally tested by our QA teams. Use at your own risk, but feel free
to enjoy and perhaps improve it while you do.

Please see the included Apache Software License for more legal details
regarding warranty.

Also as this is a 0.x release the API is still in flux and may change. Make sure
you read the release notes before upgrading.

### Downloading

If you are intending to use this module it is recommended you obtain this from the
forge and not Github:

    http://forge.puppetlabs.com/puppetlabs/firewall

The forge releases are vetted releases. Using code from Github means you are
accessing a development version or early release of the code.

### Installation

Using the puppet-module gem, you can install it into your Puppet's 
module path. If you are not sure where your module path is try 
this command:

    puppet --configprint modulepath

Firstly change into that directory. For example:

    cd /etc/puppet/modules

Then run the module tool:

    puppet-module install puppetlabs-firewall

This module uses both Ruby based providers so your Puppet configuration
(ie. puppet.conf) must include the following items:

    [agent]
    pluginsync = true

The module will not operate normally without these features enabled for the
client.

If you are using environments or with certain versions of Puppet you may
need to run Puppet on the master first:

    puppet agent -t --pluginsync --environment production

You may also need to restart Apache, although this shouldn't always be the
case.

### Examples

Basic accept ICMP request example:

    firewall { "000 accept all icmp requests":
      proto => "icmp",
      action => "accept",
    }

Drop all:

    firewall { "999 drop all other requests":
      action => "drop",
    }

Source NAT example (perfect for a virtualization host):

    firewall { '100 snat for network foo2':
      chain  => 'POSTROUTING',
      jump   => 'MASQUERADE',
      proto  => 'all',
      outiface => "eth0",
      source => ['10.1.2.0/24'],
      table  => 'nat',
    }

You can make firewall rules persistent with the following iptables example:

    exec { "persist-firewall":
      command => $operatingsystem ? {
        "debian" => "/sbin/iptables-save > /etc/iptables/rules.v4",
        /(RedHat|CentOS)/ => "/sbin/iptables-save > /etc/sysconfig/iptables",
      }
      refreshonly => true,
    }
    Firewall {
      notify => Exec["persist-firewall"]
    }

If you wish to ensure any reject rules are executed last, try using stages.
The following example shows the creation of a class which is where your
last rules should run, this however should belong in a puppet module.

    class my_fw::drop {
      iptables { "999 drop all":
        action => "drop"
      }
    }

    stage { pre: before => Stage[main] }
    stage { post: require => Stage[main] }

    class { "my_fw::drop": stage => "post" }

By placing the 'my_fw::drop' class in the post stage it will always be inserted
last thereby avoiding locking you out before the accept rules are inserted.

### Further documentation

More documentation is available from the forge for each release:

    <http://forge.puppetlabs.com/puppetlabs/firewall>

Or you can access the inline documentation:

    puppet describe firewall

Or:

    puppet doc -r type

(and search for firewall).

### Bugs

Bugs can be reported in the Puppetlabs Redmine project:

    <http://projects.puppetlabs.com/projects/modules/>

## Developer Guide

### Contributing

Make sure you read CONTRIBUTING.md before contributing.

Currently we support:

* iptables
* ip6tables

But plans are to support lots of other firewall implementations:

* FreeBSD (ipf)
* Mac OS X (ipfw)
* OpenBSD (pf)
* Cisco (ASA and basic access lists)

If you have knowledge in these technology, know how to code and wish to contribute 
to this project we would welcome the help.

### Testing

Make sure you have:

    rake

Install the necessary gems:

    gem install rspec

And run the tests from the root of the source code:

    rake test
