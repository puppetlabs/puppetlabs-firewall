## puppetlabs-firewall module

## User Guide

### Overview

This module provides the resource 'firewall' which provides the capability to
manage firewall rules within puppet.

Current support includes:

* iptables
* ip6tables

With the resource 'firewallchain' we also provide a mechanism to manage chains
for:

* iptables
* ip6tables
* ebtables

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

### Recommended Setup

At the moment you need to provide some setup outside of what we provide in the 
module to support proper ordering, purging and firewall peristence.

So It is recommended that you provide the following in top scope somewhere
(such as your site.pp):

    # Always persist firewall rules
    exec { 'persist-firewall':
      command     => $operatingsystem ? {
        'debian'          => '/sbin/iptables-save > /etc/iptables/rules.v4',
        /(RedHat|CentOS)/ => '/sbin/iptables-save > /etc/sysconfig/iptables',
      },
      refreshonly => true,
    }

    # These defaults ensure that the persistence command is executed after 
    # every change to the firewall, and that pre & post classes are run in the
    # right order to avoid potentially locking you out of your box during the
    # first puppet run.
    Firewall {
      notify  => Exec['persist-firewall'],
      before  => Class['my_fw::post'],
      require => Class['my_fw::pre'],
    }
    Firewallchain {
      notify  => Exec['persist-firewall'],
    }
    
    # Purge unmanaged firewall resources
    #
    # This will clear any existing rules, and make sure that only rules
    # defined in puppet exist on the machine
    resources { "firewall":
      purge => true
    }

In this case, it uses classes called 'my_fw::pre' & 'my_fw::post' to define
default pre and post rules. These rules are required to run in catalog order
to avoid locking yourself out of your own boxes when Puppet runs, as
the firewall class applies rules as it processes the catalog.

An example of the pre class would be:

    # This would be located in my_fw/manifests/pre.pp
    class my_fw::pre {
      Firewall {
        require => undef,
      }
    
      # Default firewall rules
      firewall { '000 accept all icmp':
        proto   => 'icmp',
        action  => 'accept',
      }->
      firewall { '001 accept all to lo interface':
        proto   => 'all',
        iniface => 'lo',
        action  => 'accept',
      }->
      firewall { '002 accept related established rules':
        proto   => 'all',
        state   => ['RELATED', 'ESTABLISHED'],
        action  => 'accept',
      }
    }

And an example of a post class:

    # This would be located in my_fw/manifests/post.pp:
    class my_fw::post {
      firewall { '999 drop all':
        proto   => 'all',
        action  => 'drop',
        before  => undef,
      }
    }

### Examples

Basic accept ICMP request example:

    firewall { "000 accept all icmp requests":
      proto  => "icmp",
      action => "accept",
    }

Drop all:

    firewall { "999 drop all other requests":
      action => "drop",
    }

Source NAT example (perfect for a virtualization host):

    firewall { '100 snat for network foo2':
      chain    => 'POSTROUTING',
      jump     => 'MASQUERADE',
      proto    => 'all',
      outiface => "eth0",
      source   => ['10.1.2.0/24'],
      table    => 'nat',
    }

Creating a new rule that forwards to a chain, then adding a rule to this chain:

    firewall { '100 forward to MY_CHAIN':
      chain   => 'INPUT',
      jump    => 'MY_CHAIN',
    }
    # The namevar here is in the format chain_name:table:protocol
    firewallchain { 'MY_CHAIN:filter:IPv4':
      ensure  => present,
    }
    firewall { '100 my rule':
      chain   => 'MY_CHAIN',
      action  => 'accept',
      proto   => 'tcp',
      dport   => 5000,
    }


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

Please note, we only aim support for the following distributions and versions:

* Redhat 5.8 or greater
* Debian 6.0 or greater
* Ubuntu 11.04 or greater

If you want a new distribution supported feel free to raise a ticket and we'll
consider it. If you want an older revision supported we'll also consider it,
but don't get insulted if we reject it. Specifically, we will not consider
Redhat 4.x support - its just too old.

## Developer Guide

### Contributing

Make sure you read CONTRIBUTING.md before contributing.

Currently we support:

* iptables
* ip6tables
* ebtables (chains only)

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
