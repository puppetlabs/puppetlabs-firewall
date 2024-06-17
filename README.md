# firewall

[![PR Testing](https://github.com/puppetlabs/puppetlabs-firewall/actions/workflows/pr_test.yml/badge.svg)](https://github.com/puppetlabs/puppetlabs-firewall/actions/workflows/pr_test.yml)

#### Table of Contents

1. [Overview - What is the firewall module?](#overview)
2. [Module description - What does the module do?](#module-description)
3. [Setup - The basics of getting started with firewall](#setup)
    * [What firewall affects](#what-firewall-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with firewall](#beginning-with-firewall)
    * [Upgrading](#upgrading)
4. [Usage - Configuration and customization options](#usage)
    * [Default rules - Setting up general configurations for all firewalls](#default-rules)
    * [Application-specific rules - Options for configuring and managing firewalls across applications](#application-specific-rules)
    * [Rule inversion](#rule-inversion)
    * [Additional uses for the firewall module](#additional-uses-for-the-firewal-module)
    * [Duplicate rule behaviour](#duplicate-rule-behaviour)
    * [Additional information](#additional-information)
5. [Reference - An under-the-hood peek at what the module is doing](#reference)
6. [Limitations - OS compatibility, etc.](#limitations)
7. [License](#license)
7. [Firewall_multi - Arrays for certain parameters](#firewall_multi)
8. [Development - Guide for contributing to the module](#development)
    * [Tests - Testing your configuration](#tests)

## Overview

The firewall module lets you manage firewall rules with Puppet.

## Module description

PuppetLabs' firewall module introduces the `firewall` resource, which is used to manage and configure firewall rules from within the Puppet DSL. This module offers support for iptables and ip6tables. The module also introduces the `firewallchain` resource, which allows you to manage chains or firewall lists and ebtables for bridging support. At the moment, only iptables and ip6tables chains are supported.

The firewall module acts on your running firewall, making immediate changes as the catalog executes. Defining default pre and post rules allows you to provide global defaults for your hosts before and after any custom rules. Defining `pre` and `post` rules is also necessary to help you avoid locking yourself out of your own boxes when Puppet runs.

## Setup

### What firewall affects

* Every node running a firewall
* Firewall settings in your system
* Connection settings for managed nodes
* Unmanaged resources (get purged)


### Setup requirements

Firewall uses Ruby-based providers, so you must enable [pluginsync](http://docs.puppetlabs.com/guides/plugins_in_modules.html#enabling-pluginsync).

### Beginning with firewall

In the following two sections, you create new classes and then create firewall rules related to those classes. These steps are optional but provide a framework for firewall rules, which is helpful if you’re just starting to create them.

If you already have rules in place, then you don’t need to do these two sections. However, be aware of the ordering of your firewall rules. The module will dynamically apply rules in the order they appear in the catalog, meaning a deny rule could be applied before the allow rules. This might mean the module hasn’t established some of the important connections, such as the connection to the Puppet server.

The following steps are designed to ensure that you keep your SSH and other connections, primarily your connection to your Puppet server. If you create the `pre` and `post` classes described in the first section, then you also need to create the rules described in the second section.

#### Create the `my_fw::pre` and `my_fw::post` Classes

This approach employs a whitelist setup, so you can define what rules you want and everything else is ignored rather than removed.

The code in this section does the following:

* The 'require' parameter in `firewall {}` ensures `my_fw::pre` is run before any other rules.
* In the `my_fw::post` class declaration, the 'before' parameter ensures `my_fw::post` is run after any other rules.

The rules in the `pre` and `post` classes are fairly general. These two classes ensure that you retain connectivity and that you drop unmatched packets appropriately. The rules you define in your manifests are likely to be specific to the applications you run.

1. Add the `pre` class to `my_fw/manifests/pre.pp`, and any default rules to your pre.pp file first — in the order you want them to run.

```puppet
class my_fw::pre {
  Firewall {
    require => undef,
  }

  # Default firewall rules
  firewall { '000 accept all icmp':
    proto => 'icmp',
    jump  => 'accept',
  }
  -> firewall { '001 accept all to lo interface':
    proto   => 'all',
    iniface => 'lo',
    jump    => 'accept',
  }
  -> firewall { '002 reject local traffic not on loopback interface':
    iniface     => '! lo',
    proto       => 'all',
    destination => '127.0.0.1/8',
    jump        => 'reject',
  }
  -> firewall { '003 accept related established rules':
    proto  => 'all',
    state  => ['RELATED', 'ESTABLISHED'],
    jump   => 'accept',
  }
}
```

The rules in `pre` allow basic networking (such as ICMP and TCP) and ensure that
existing connections are not closed.

2. Add the `post` class to `my_fw/manifests/post.pp` and include any default rules — apply these last.

```puppet
class my_fw::post {
  firewall { '999 drop all':
    proto  => 'all',
    jump   => 'drop',
    before => undef,
  }
}
```

Alternatively, the [firewallchain](#type-firewallchain) type can be used to set the default policy:

```puppet
firewallchain { 'INPUT:filter:IPv4':
  ensure => present,
  policy => drop,
  before => undef,
}
```

#### Create firewall rules

The rules you create here are helpful if you don’t have any existing rules; they help you order your firewall configurations so you don’t lock yourself out of your box.

Rules are persisted automatically between reboots, although there are known issues with ip6tables on older Debian/Ubuntu distributions. There are also known issues with ebtables.

1. Use the following code to set up the default parameters for all of the firewall rules that you will establish later. These defaults will ensure that the `pre` and `post` classes are run in the correct order and avoid locking you out of your box during the first Puppet run.

```puppet
Firewall {
  before  => Class['my_fw::post'],
  require => Class['my_fw::pre'],
}
```

2. Declare the `my_fw::pre` and `my_fw::post` classes to satisfy dependencies. You can declare these classes using an external node classifier or the following code:

```puppet
class { ['my_fw::pre', 'my_fw::post']: }
```

3. Include the `firewall` class to ensure the correct packages are installed:

```puppet
class { 'firewall': }
```

4. If you want to remove unmanaged firewall rules, add the following code to set up a metatype to purge unmanaged firewall resources in your site.pp or another top-scope file. This will clear any existing rules and make sure that only rules defined in Puppet exist on the machine.

```puppet
resources { 'firewall':
  purge => true,
}
```

  To purge unmanaged firewall chains, add:

```puppet
resources { 'firewallchain':
  purge => true,
}
```

Internal chains can not be deleted. In order to avoid all the confusing
Warning/Notice messages when using `purge => true`, like these ones:

  Warning: Inbuilt Chains may not be deleted. Chain `POSTROUTING:mangle:IPv6` will be flushed and have it's policy reverted to default.

  Please create firewallchains for every internal chain. Here is an example:

```puppet
firewallchain { 'POSTROUTING:mangle:IPv6':
  ensure  => present,
}

resources { 'firewallchain':
  purge => true,
}
```

> **Note:** If you need more fine-grained control about which unmananged rules get removed, investigate the `purge` and `ignore_foreign` parameters available in `firewallchain`.

> **Note:** `ignore_foreign` of `firewallchain` does not work as expected with a resources purge of `firewall`.

### Upgrading

Use these steps if you already have a version of the firewall module installed.

#### From version 0.2.0 and more recent

Upgrade the module with the puppet module tool as normal:

    puppet module upgrade puppetlabs/firewall

## Usage

There are two kinds of firewall rules you can use with firewall: default rules and application-specific rules. Default rules apply to general firewall settings, whereas application-specific rules manage firewall settings for a specific application, node, etc.

All rules employ a numbering system in the resource's title that is used for ordering. When titling your rules, make sure you prefix the rule with a number, for example, '000 accept all icmp requests'. _000_ runs first, _999_ runs last.

**Note:** The ordering range 9000-9999 is reserved for unmanaged rules. Do not specify any firewall rules in this range.

### Default rules

You can place default rules in either `my_fw::pre` or `my_fw::post`, depending on when you would like them to run. Rules placed in the `pre` class will run first, and rules in the `post` class, last.

In iptables, the title of the rule is stored using the comment feature of the underlying firewall subsystem. Values must match '/^\d+[[:graph:][:space:]]+$/'.

#### Examples of default rules

Basic accept ICMP request example:

```puppet
firewall { '000 accept all icmp requests':
  proto => 'icmp',
  jump  => 'accept',
}
```

Drop all:

```puppet
firewall { '999 drop all other requests':
  jump => 'drop',
}
```

#### Example of an IPv6 rule

IPv6 rules can be specified using the _ip6tables_ provider:

```puppet
firewall { '006 Allow inbound SSH (v6)':
  dport    => 22,
  proto    => 'tcp',
  jump     => 'accept',
  protocol => 'ip6tables',
}
```

### Application-specific rules

Puppet doesn't care where you define rules, and this means that you can place
your firewall resources as close to the applications and services that you
manage as you wish. If you use the [roles and profiles
pattern](https://puppetlabs.com/learn/roles-profiles-introduction) then it
makes sense to create your firewall rules in the profiles, so they
remain close to the services managed by the profile.

This is an example of firewall rules in a profile:

```puppet
class profile::apache {
  include apache
  apache::vhost { 'mysite':
    ensure => present,
  }

  firewall { '100 allow http and https access':
    dport  => [80, 443],
    proto  => 'tcp',
    jump   => 'accept',
  }
}
```

### Rule inversion

Firewall rules may be inverted by prefixing the value of a parameter by "! ".

Parameters that understand inversion are: connmark, ctstate, destination, dport, dst\_range, dst\_type, iniface, outiface, port, proto, source, sport, src\_range and src\_type.

If the value is an array, then either the first value of the array, or all of its values must be prefixed in order to invert them all.
For most array attributes it is not possible to invert only one passed value.

Examples:

```puppet
firewall { '001 disallow esp protocol':
  jump   => 'accept',
  proto  => '! esp',
}

firewall { '002 drop NEW external website packets with FIN/RST/ACK set and SYN unset':
  chain     => 'INPUT',
  state     => 'NEW',
  jump      => 'drop',
  proto     => 'tcp',
  sport     => ['! http', '443'],
  source    => '! 10.0.0.0/8',
  tcp_flags => '! FIN,SYN,RST,ACK SYN',
}
```

There are exceptions to this however, with attributes such as src\_type, dst\_type and ipset allowing the user to negate each passed values seperately.

Examples:

```puppet
firewall { '001 allow local disallow anycast':
  jump     => 'accept',
  src_type => ['LOCAL', '! ANYCAST'],
}
```

### Additional uses for the firewall module

You can apply firewall rules to specific nodes. Usually, you should put the firewall rule in another class and apply that class to a node. Apply a rule to a node as follows:

```puppet
node 'some.node.com' {
  firewall { '111 open port 111':
    dport => 111,
  }
}
```

You can also do more complex things with the `firewall` resource. This example sets up static NAT for the source network 10.1.2.0/24:

```puppet
firewall { '100 snat for network foo2':
  chain    => 'POSTROUTING',
  jump     => 'MASQUERADE',
  proto    => 'all',
  outiface => 'eth0',
  source   => '10.1.2.0/24',
  table    => 'nat',
}
```


You can also change the TCP MSS value for VPN client traffic:

```puppet
firewall { '110 TCPMSS for VPN clients':
  chain     => 'FORWARD',
  table     => 'mangle',
  source    => '10.0.2.0/24',
  proto     => 'tcp',
  tcp_flags => 'SYN,RST SYN',
  mss       => '1361:1541',
  set_mss   => '1360',
  jump      => 'TCPMSS',
}
```

The following will mirror all traffic sent to the server to a secondary host on the LAN with the TEE target:

```puppet
firewall { '503 Mirror traffic to IDS':
  proto   => 'all',
  jump    => 'TEE',
  gateway => '10.0.0.2',
  chain   => 'PREROUTING',
  table   => 'mangle',
}
```

The following example creates a new chain and forwards any port 5000 access to it.

```puppet
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
  jump    => 'accept',
  proto   => 'tcp',
  dport   => 5000,
}
```

Setup NFLOG for a rule.

```puppet
firewall {'666 for NFLOG':
  proto           => 'all',
  jump            => 'NFLOG',
  nflog_group     => 3,
  nflog_prefix    => 'nflog-test',
  nflog_size      => 256,
  nflog_threshold => 1,
}
```

### Duplicate rule behaviour

It is possible for an unmanaged rule to exist on the target system that has the same comment as the rule specified in the manifest. This configuration is not supported by the firewall module.

In the event of a duplicate rule, the module will throw an error message notifying the user that it has found a duplicate and halt in it's update.

This behaviour was previously configurable via the `onduplicaterulebehaviour` parameter. However the implementation of this resulted in a massive slowdown of the module and so this has been removed in favour of a simple error being thrown whenever a duplicate is detected.

### Additional information

Access the inline documentation:

    puppet describe firewall

Or

    puppet doc -r type
    (and search for firewall)

## Reference

For information on the classes and types, see the [REFERENCE.md](https://github.com/puppetlabs/puppetlabs-firewall/blob/main/REFERENCE.md). For information on the facts, see below.

Facts:

* [ip6tables_version](#fact-ip6tablesversion)
* [iptables_version](#fact-iptablesversion)
* [iptables_persistent_version](#fact-iptablespersistentversion)

### Fact: ip6tables_version

A Facter fact that can be used to determine what the default version of ip6tables is for your operating system/distribution.

### Fact: iptables_version

A Facter fact that can be used to determine what the default version of iptables is for your operating system/distribution.

### Fact: iptables_persistent_version

Retrieves the version of iptables-persistent from your OS. This is a Debian/Ubuntu specific fact.

## Limitations

For an extensive list of supported operating systems, see [metadata.json](https://github.com/puppetlabs/puppetlabs-firewall/blob/main/metadata.json)

### SLES

The `socket` parameter is not supported on SLES.  In this release it will cause
the catalog to fail with iptables failures, rather than correctly warn you that
the features are unusable.

### Oracle Enterprise Linux

The `socket` and `owner` parameters are unsupported on Oracle Enterprise Linux
when the "Unbreakable" kernel is used. These may function correctly when using
the stock RedHat kernel instead. Declaring either of these parameters on an
unsupported system will result in iptable rules failing to apply.

## Passing firewall parameter values as arrays with `firewall_multi` module

You might sometimes need to pass arrays, such as arrays of source or destination addresses, to some parameters in contexts where iptables itself does not allow arrays.

A community module, [alexharvey-firewall_multi](https://forge.puppet.com/alexharvey/firewall_multi), provides a defined type wrapper to spawn firewall resources for arrays of certain inputs.

For example:

```puppet
firewall_multi { '100 allow http and https access':
  source => [
    '10.0.10.0/24',
    '10.0.12.0/24',
    '10.1.1.128',
  ],
  dport  => [80, 443],
  proto  => 'tcp',
  jump   => 'accept',
}
```

For more information see the documentation at [alexharvey-firewall_multi](https://forge.puppet.com/alexharvey/firewall_multi).

### Known issues

#### MCollective causes PE to reverse firewall rule order

Firewall rules appear in reverse order if you use MCollective to run Puppet in Puppet Enterprise 2016.1, 2015.3, 2015.2, or 3.8.x.

If you use MCollective to kick off Puppet runs (`mco puppet runonce -I agent.example.com`) while also using the [`puppetlabs/firewall`](https://forge.puppet.com/puppetlabs/firewall) module, your firewall rules might be listed in reverse order.

In many firewall configurations, the last rule drops all packets. If the rule order is reversed, this rule is listed first and network connectivity fails.

To prevent this issue, do not use MCollective to kick off Puppet runs. Use any of the following instead:

* Run `puppet agent -t` on the command line.
* Use a cron job.
* Click [Run Puppet](https://docs.puppet.com/pe/2016.1/console_classes_groups_running_puppet.html#run-puppet-on-an-individual-node) in the console.

### condition parameter

The `condition` parameter requires `xtables-addons` to be installed locally.
For ubuntu distributions `xtables-addons-common` package can be installed by running command: `apt-get install xtables-addons-common` or
running a manifest:

```puppet
package { 'xtables-addons-common':
  ensure => 'latest',
}
```

For other distributions (RedHat, Debian, Centos etc) manual installation of the `xtables-addons` package is required.

#### Reporting Issues

Please report any bugs in the Puppetlabs GitHub issue tracker:

<https://github.com/puppetlabs/puppetlabs-firewall/issues>

## License

This codebase is licensed under the Apache2.0 licensing, however due to the nature of the codebase the open source dependencies may also use a combination of [AGPL](https://opensource.org/license/agpl-v3/), [BSD-2](https://opensource.org/license/bsd-2-clause/), [BSD-3](https://opensource.org/license/bsd-3-clause/), [GPL2.0](https://opensource.org/license/gpl-2-0/), [LGPL](https://opensource.org/license/lgpl-3-0/), [MIT](https://opensource.org/license/mit/) and [MPL](https://opensource.org/license/mpl-2-0/) Licensing.

## Development

Acceptance tests for this module leverage [puppet_litmus](https://github.com/puppetlabs/puppet_litmus).
To run the acceptance tests follow the instructions [here](https://github.com/puppetlabs/puppet_litmus/wiki/Tutorial:-use-Litmus-to-execute-acceptance-tests-with-a-sample-module-(MoTD)#install-the-necessary-gems-for-the-module).
You can also find a tutorial and walkthrough of using Litmus and the PDK on [YouTube](https://www.youtube.com/watch?v=FYfR7ZEGHoE).

If you run into an issue with this module, or if you would like to request a feature, please [file a ticket](https://github.com/puppetlabs/puppetlabs-firewall/issues).
Every Monday the Puppet IA Content Team has [office hours](https://puppet.com/community/office-hours) in the [Puppet Community Slack](http://slack.puppet.com/), alternating between an EMEA friendly time (1300 UTC) and an Americas friendly time (0900 Pacific, 1700 UTC).

If you have problems getting this module up and running, please [contact Support](http://puppetlabs.com/services/customer-support).

If you submit a change to this module, be sure to regenerate the reference documentation as follows:

```bash
puppet strings generate --format markdown --out REFERENCE.md
```

### Testing

Make sure you have:

* rake
* bundler

Install the necessary gems:

```text
bundle install
```

And run the tests from the root of the source code:

```text
bundle exec rake parallel_spec
```

See the Github Action runs for information on running the acceptance and other tests.

### Migration path to v7.0.0

As of `v7.0.0` of this module a major rework has been done to adopt the [puppet-resource_api](https://github.com/puppetlabs/puppet-resource_api) into the module and use it style of code in place of the original form of Puppet Type and Providers. This was done in the most part to increase the ease with with the module could be maintained and updated in the future, the changes helping to structure the module in such a way as to be more easily understood and altered going forward.

As part of this process several breaking changes where made to the code that will need to be accounted for whenever you update to this new version of the module, with these changes including:

* The `provider` attibute within the `firewall` type has been renamed to `protocol`, both to bring it in line with the matching attribute within the `firewallchain` type and due to the resource_api forbidding the use of `provider` as a attribute name. As part of this the attribute has also been updated to accept `IPv4` and `IPv6` in place of `iptables` or `ip6tables`, though they are still valid as input.
* The `action` attribute within the `firewall` type has been removed as it was merely a restricted version of the `jump` attribute, both of them managing the same function, this being reasoned as a way to enforce the use of generic parameters. From this point the parameters formerly unique to `action` should now be passed to `jump`.
* Strict types have now been implemented for all attributes, while this should not require changes on the user end in most cases, there may be some instances where manifests will require updated to match the new expected form of input.
* Attributes that allow both arrays and negated values have now been updated.
  * For attributes that require that all passed values be negated as one, you now merely have to negate the first value within the array, rather than all of them, though negating all is still accepted.
  * For attributes that allow passed values to be negated seperately this is not the case. All attributes in this situation are noted within their description.
* The `sport` and `dport` attributes have been updated so that they will now accept with `:` or `-` as a separator when passing ranges, with `:` being preferred as it matches what is passed to iptables.

Two pairs of manifest taken from the tests can be seen below, illustrating the changes that may be required, the first applying a hoplimit on `ip6tables`:

```Puppet
firewall { '571 - hop_limit':
  ensure    => present,
  proto     => 'tcp',
  dport     => '571',
  action    => 'ACCEPT',
  hop_limit => '5',
  provider  => 'ip6tables',
}
```

```Puppet
firewall { '571 - hop_limit':
  ensure    => present,
  proto     => 'tcp',
  dport     => '571',
  jump      => 'accept',
  hop_limit => '5',
  protocol  => 'IPv6',
}
```

And the second negating access to a range of ports on `iptables`:

```puppet
firewall { '560 - negated ports':
  proto  => `tcp`,
  sport  => ['! 560-570','! 580'],
  action => `accept`,
}
```

```puppet
firewall { '560 - negated ports':
  proto  => `tcp`,
  sport  => '! 560:570','580',
  jump   => `accept`,
}
```
