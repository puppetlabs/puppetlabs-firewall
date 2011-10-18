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

This module uses both Ruby based providers so your Puppet configuration (ie. puppet.conf) must include the following items:

    [agent]
    pluginsync = true
    
The module will not operate normally without these features enabled.

### Quickstart

Once the module is in the correct modulepath, you should be able to create some
firewall rules like the below examples. Remember, that rules are lexically 
ordered by the resource title at this point.

Basic accept ICMP request example:

    firewall { "000 accept all icmp requests":
      proto => "icmp",
      action => "accept",
    }

Deny all:

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

### Generic Properties

#### ensure

Creates rule when present, removes it when absent.

#### name

* namevar

Name of firewall rule. This at the moment also is used for ordering, so its
common practice to prefix all rules with numbers to force ordering. For example:

    name => "000 accept local traffic"

This will occur very early.

#### action

This is the action to perform on a match. Can be one of:

* accept - the packet is accepted
* reject - the packet is rejected with a suitable ICMP response
* drop - the packet is dropped

If you specify no value it will simply match the rule but perform no
action unless you provide a provider specific parameter (such as 'jump').

#### proto

Protocol to filter. By default this is 'tcp'.

#### source

An array of source addresses. For example:

    source => ['192.168.2.0/24', '10.2.3.0/24']

#### destination

An array of destination addresses to match. For example:

    destination => ['192.168.2.0/24', '10.2.3.0/24']

#### sport

For protocols that support ports, this is a list of source ports to filter on.

#### dport

For protocols that support ports, this is a list of destination ports to filter on.

### Iptables Properties

#### chain

Name of the chain to use. Can be one of the built-ins:

* INPUT
* FORWARD
* OUTPUT
* PREROUTING
* POSTROUTING

Or you can provide a user-based chain.

The default value is 'INPUT'.

#### table

Table to use. Can be one of:

* nat
* mangle
* filter
* raw
* rawpost

By default the setting is 'filter'.

#### jump

Action to perform when filter is matched for iptables. Can be one of:

* QUEUE
* RETURN
* DNAT
* SNAT
* LOG
* MASQUERADE
* REDIRECT

But any valid chain name is allowed. 

For the values ACCEPT, DROP and REJECT you must use the generic 
'action' parameter. This is to enfore the use of generic parameters where
possible for maximum cross-platform modelling.

If you set both 'accept' and 'jump' parameters, you will get an error as 
only one of the options should be set.

### Interface Matching Properties

#### iniface

Input interface to filter on.

#### outiface

Output interface to filter on.

### NAT Properties

#### tosource

When using jump => "SNAT" you can specify the new source address using this
parameter.

#### todestination

When using jump => "DNAT" you can specify the new destination address using
this paramter.

#### toports

Specifies a range of ports to use for masquerade.

### Reject Properties

#### reject

When combined with jump => "REJECT" you can specify a different icmp response
to be sent back to the packet sender.

### Logging Properties

#### log_level

When combined with jump => "LOG" specifies the log level to log to.

#### log_prefix

When combined with jump => "LOG" specifies the log prefix to use when logging.

### ICMP Matching Properties

#### icmp

Specifies the type of ICMP to match.

### State Matching Properties

#### state

When matching using stateful inspection you can match on different states such
as:

* INVALID
* ESTABLISHED
* NEW
* RELATED

### Rate Limiting Properties

#### limit

A rate to limit matched packets in the form of:

    rate/[/second/|/minute|/hour|/day]

#### burst

Maximum initial packets to match before limit checks (above) apply.

### Testing

Make sure you have:

    rake

Install the necessary gems:

    gem install rspec

And run the tests from the root of the source code:

    rake test
