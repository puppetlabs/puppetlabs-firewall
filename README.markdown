#firewall

[![Build Status](https://travis-ci.org/puppetlabs/puppetlabs-firewall.png?branch=master)](https://travis-ci.org/puppetlabs/puppetlabs-firewall)

####Table of Contents

1. [Overview - What is the Firewall module?](#overview)
2. [Module Description - What does the module do?](#module-description)
3. [Setup - The basics of getting started with Firewall](#setup)
    * [What Firewall Affects](#what-firewall-affects)
    * [Setup Requirements](#setup-requirements)
    * [Beginning with Firewall](#beginning-with-firewall)
    * [Upgrading](#upgrading)
4. [Usage - Configuration and customization options](#usage)
    * [Default rules - Setting up general configurations for all firewalls](#default-rules)
    * [Application-Specific Rules - Options for configuring and managing firewalls across applications](#application-specific-rules)
    * [Additional Uses for the Firewall Module](#other-rules)
5. [Reference - An under-the-hood peek at what the module is doing](#reference)
6. [Limitations - OS compatibility, etc.](#limitations)
7. [Development - Guide for contributing to the module](#development)
    * [Tests - Testing your configuration](#tests)

##Overview

The Firewall module lets you manage firewall rules with Puppet. 

##Module Description

PuppetLabs' Firewall module introduces the `firewall` resource, which is used to manage and configure firewall rules from within the Puppet DSL. This module offers support for iptables and ip6tables. The module also introduces the `firewallchain` resource, which allows you to manage chains or firewall lists and ebtables for bridging support. At the moment, only iptables and ip6tables chains are supported.

The Firewall module acts on your running firewall, making immediate changes as the catalog executes. Defining default pre and post rules allows you to provide global defaults for your hosts before and after any custom rules. Defining `pre` and `post` rules is also necessary to help you avoid locking yourself out of your own boxes when Puppet runs. 

##Setup

###What Firewall Affects

* Every node running a firewall
* Firewall Settings in Your System
* Connection settings for managed nodes
* Unmanaged resources (get purged)


###Setup Requirements

Firewall uses Ruby-based providers, so you must enable [pluginsync enabled](http://docs.puppetlabs.com/guides/plugins_in_modules.html#enabling-pluginsync).

###Beginning with Firewall

In the following two sections, you create new classes and then create firewall rules related to those classes. These steps are optional, but provide a framework for firewall rules, which is helpful if you’re just starting to create them. 

If you already have rules in place, then you don’t need to do these two sections. However, be aware of the ordering of your firewall rules. The module will dynamically apply rules in the order they appear in the catalog, meaning a deny rule could be applied before the allow rules. This might mean the module hasn’t established some of the important connections, such as the connection to the Puppet master. 

The following steps are designed to ensure that you keep your SSH and other connections, primarily your connection to your Puppet master. If you create the `pre` and `post` classes described in the first section, then you also need to create the rules described in the second section.

####Create the `my_fw::pre` and `my_fw::post` Classes

This approach employs a whitelist setup, so you can define what rules you want and everything else is ignored rather than removed.

The code in this section does the following: 
* The `require` parameter in `Firewall {}` ensures `my_fw::pre` is run before any other rules.  
* In the `my_fw::post` class declaration, the `before` parameter ensures `my_fw::post` is run after any other rules. 

Therefore, the run order is:

* The rules in `my_fw::pre`
* Your rules (defined in code)
* The rules in `my_fw::post`

The rules in the `pre` and `post` classes are fairly general. These two classes ensure that you retain connectivity, and that you drop unmatched packets appropriately. The rules you define in your manifests are likely specific to the applications you run. 

1. Add the `pre` class to `my_fw/manifests/pre.pp`. `pre.pp` should contain any default rules to be applied first. The rules in this class should be added in the order you want them to run.

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
        ctstate => ['RELATED', 'ESTABLISHED'],
        action  => 'accept',
      }
    }

The rules in `pre` should allow basic networking (such as ICMP and TCP), and ensure that existing connections are not closed.

2. Add the `post` class to `my_fw/manifests/post.pp` and include any default rules to be applied last.

    class my_fw::post {
      firewall { '999 drop all':
        proto   => 'all',
        action  => 'drop',
        before  => undef,
      }
    }

####Create Firewall Rules

The rules you create here are helpful if you don’t have any existing rules; they help you order your firewall configurations so you don’t lock yourself out of your box.

Rules are persisted automatically between reboots, although there are known issues with ip6tables on older Debian/Ubuntu distributions. There are also known issues with ebtables.

1. In `site.pp` or another top-scope file, add the following code to set up a metatype to purge unmanaged firewall resources. This will clear any existing rules and make sure that only rules defined in Puppet exist on the machine. 

**Note** - This only purges IPv4 rules. 

    resources { "firewall":
      purge => true
    }

2.  Use the following code to set up the default parameters for all of the firewall rules you will establish later. These defaults will ensure that the `pre` and `post` classes are run in the correct order to avoid locking you out of your box during the first Puppet run.

    Firewall {
      before  => Class['my_fw::post'],
      require => Class['my_fw::pre'],
    }

3. Then, declare the `my_fw::pre` and `my_fw::post` classes to satisfy dependencies. You can declare these classes using an **External Node Classifier** or the following code:

    class { ['my_fw::pre', 'my_fw::post']: }

4. Include the `firewall` class to ensure the correct packages are installed.

    class { 'firewall': }

###Upgrading

Use these steps if you already have a version of the Firewall module installed.

####From version 0.2.0 and more recent

Upgrade the module with the puppet module tool as normal:

    puppet module upgrade puppetlabs/firewall


##Usage

There are two kinds of firewall rules you can use with Firewall: default rules and application-specific rules. Default rules apply to general firewall settings, whereas application-specific rules manage firewall settings for a specific application, node, etc.

All rules employ a numbering system in the resource's title that is used for ordering. When titling your rules, make sure you prefix the rule with a number, for example, `000 accept all icmp requests`

      000 runs first
      999 runs last

###Default Rules

You can place default rules in either `my_fw::pre` or `my_fw::post`, depending on when you would like them to run. Rules placed in the `pre` class will run first, and rules in the `post` class, last.

In iptables, the title of the rule is stored using the comment feature of the underlying firewall subsystem. Values can match `/^\d+[[:alpha:][:digit:][:punct:][:space:]]+$/`.

####Examples of Default Rules

Basic accept ICMP request example:

    firewall { "000 accept all icmp requests":
      proto  => "icmp",
      action => "accept",
    }

Drop all:

    firewall { "999 drop all other requests":
      action => "drop",
    }

###Application-Specific Rules

Puppet doesn't care where you define rules, and this means that you can place
your firewall resources as close to the applications and services that you
manage as you wish.  If you use the [roles and profiles
pattern](https://puppetlabs.com/learn/roles-profiles-introduction) then it
makes sense to create your firewall rules in the profiles, so that they
remain close to the services managed by the profile.

This is an example of firewall rules in a profile:

```puppet
class profile::apache {
  include apache
  apache::vhost { 'mysite': ensure => present }

  firewall { '100 allow http and https access':
    port   => [80, 443],
    proto  => tcp,
    action => accept,
  }
}
```


###Additional Uses for the Firewall Module

You can apply firewall rules to specific nodes. Usually, you will want to put the firewall rule in another class and apply that class to a node. Apply a rule to a node as follows:

    node 'some.node.com' {
      firewall { '111 open port 111':
        dport => 111
      }
    }

You can also do more complex things with the `firewall` resource. This example sets up static NAT for the source network 10.1.2.0/24:

    firewall { '100 snat for network foo2':
      chain    => 'POSTROUTING',
      jump     => 'MASQUERADE',
      proto    => 'all',
      outiface => "eth0",
      source   => '10.1.2.0/24',
      table    => 'nat',
    }

The following example creates a new chain and forwards any port 5000 access to it.

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

###Additional Information

Access the inline documentation:

    puppet describe firewall

Or

    puppet doc -r type
    (and search for firewall)

##Reference

Classes:

* [firewall](#class-firewall)

Types:

* [firewall](#type-firewall)
* [firewallchain](#type-firewallchain)

Facts:

* [ip6tables_version](#fact-ip6tablesversion)
* [iptables_version](#fact-iptablesversion)
* [iptables_persistent_version](#fact-iptablespersistentversion)

###Class: firewall

Performs the basic setup tasks required for using the firewall resources.

At the moment this takes care of:

* iptables-persistent package installation

Include the `firewall` class for nodes that need to use the resources in this module:

    class { 'firewall': }

####`ensure`

Parameter that controls the state of the `iptables` service on your system, allowing you to disable `iptables` if you want.

`ensure` can either be `running` or `stopped`. Default to `running`.

###Type: firewall

Enables you to manage firewall rules within Puppet.

For more information on Firewall types, see the [Types tab](http://forge.puppetlabs.com/puppetlabs/firewall#types).

###Type:: firewallchain

Enables you to manage rule chains for firewalls.

Currently this type supports only iptables, ip6tables, and ebtables on Linux. It also provides support for setting the default policy on chains and tables that allow it.


For more information on Firewall types, see the [Types tab](http://forge.puppetlabs.com/puppetlabs/firewall#types).


###Fact: ip6tables_version

A Facter fact that can be used to determine what the default version of ip6tables is for your operating system/distribution.

###Fact: iptables_version

A Facter fact that can be used to determine what the default version of iptables is for your operating system/distribution.

###Fact: iptables_persistent_version

Retrieves the version of iptables-persistent from your OS. This is a Debian/Ubuntu specific fact.

##Limitations

###SLES

The `socket` parameter is not supported on SLES.  In this release it will cause
the catalog to fail with iptables failures, rather than correctly warn you that
the features are unusable.

###Oracle Enterprise Linux

The `socket` and `owner` parameters are unsupported on Oracle Enterprise Linux
when the "Unbreakable" kernel is used. These may function correctly when using
the stock RedHat kernel instead. Declaring either of these parameters on an
unsupported system will result in iptable rules failing to apply.

###Other

Bugs can be reported using JIRA issues

<http://tickets.puppetlabs.com>

##Development

Puppet Labs modules on the Puppet Forge are open projects, and community contributions are essential for keeping them great. We can’t access the huge number of platforms and myriad of hardware, software, and deployment configurations that Puppet is intended to serve.

We want to keep it as easy as possible to contribute changes so that our modules work in your environment. There are a few guidelines that we need contributors to follow so that we can have a chance of keeping on top of things.

You can read the complete module contribution guide [on the Puppet Labs wiki.](http://projects.puppetlabs.com/projects/module-site/wiki/Module_contributing)

For this particular module, please also read CONTRIBUTING.md before contributing.

Currently we support:

* iptables
* ip6tables
* ebtables (chains only)

###Testing

Make sure you have:

* rake
* bundler

Install the necessary gems:

    bundle install

And run the tests from the root of the source code:

    rake test

If you have a copy of Vagrant 1.1.0 you can also run the system tests:

    RS_SET=ubuntu-1404-x64 rspec spec/acceptance
    RS_SET=centos-64-x64 rspec spec/acceptance



