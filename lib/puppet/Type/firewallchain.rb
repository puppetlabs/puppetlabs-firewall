# lib/puppet/type/firewallchain.rb
require 'puppet/resource_api'

Puppet::ResourceApi.register_type(
  name: 'firewallchain',
  docs: <<-EOS,
    This type provides the capability to manage rule chains for firewalls.

  Currently this supports only iptables, ip6tables and ebtables on Linux. And
  provides support for setting the default policy on chains and tables that
  allow it.

  **Autorequires:**
  If Puppet is managing the iptables, iptables-persistent, or iptables-services packages,
  and the provider is iptables_chain, the firewall resource will autorequire
  those packages to ensure that any required binaries are installed.

  #### Providers
    * iptables_chain is the only provider that supports firewallchain.

  #### Features
    * iptables_chain: The provider provides iptables chain features.
    * policy: Default policy (inbuilt chains only).
    EOS
  attributes: {
    ensure: {
      type:    'Enum[present, absent]',
      desc:    'Whether this chain should be present or absent on the target system.',
      default: 'present',
    },
    name: {
      type:      'Pattern[/^(.+):(nat|mangle|filter|raw|rawpost|broute|security):(IP(v[46])?|ethernet)$/]',
      desc:      'The canonical name of the chain. The format for this must be {chain}:{table}:{protocol}.',
      behaviour: :namevar,
    },
    policy: {
      type:      "Optional[Enum['accept', 'drop', 'queue', 'return']]",
      desc:      <<-EOS,
      This action to take when the end of the chain is reached.
      It can only be set on inbuilt chains (INPUT, FORWARD, OUTPUT,
      PREROUTING, POSTROUTING) and can be one of:

      * accept - the packet is accepted
      * drop - the packet is dropped
      * queue - the packet is passed userspace
      * return - the packet is returned to calling (jump) queue
                 or the default of inbuilt chains
      
      Will default to `accept` when an `ethernet` protocol is given.
      EOS
    },
    ignore: {
      type:      'Optional[Variant[String[1], Array[String[1]]]',
      desc:      <<-EOS
      Regex to perform on firewall rules to exempt unmanaged rules from purging.
      This is matched against the output of `iptables-save`.

      This can be a single regex, or an array of them.
      To support flags, use the ruby inline flag mechanism.
      Meaning a regex such as
        /foo/i
      can be written as
        '(?i)foo' or '(?i:foo)'

      Full example:
      ```
      firewallchain { 'INPUT:filter:IPv4':
        purge => true,
        ignore => [
          '-j fail2ban-ssh', # ignore the fail2ban jump rule
          '--comment "[^"]*(?i:ignore)[^"]*"', # ignore any rules with "ignore" (case insensitive) in the comment in the rule
        ],
      }
      ```
      EOS
    },
    ignore_foreign: {
      type:      'Bolean',
      desc:      <<-EOS
      Ignore rules that do not match the puppet title pattern "^\d+[[:graph:][:space:]]" when purging unmanaged firewall rules in this chain.
      This can be used to ignore rules that were not put in by puppet. Beware that nothing keeps other systems from configuring firewall rules with a comment that starts with digits, and is indistinguishable from puppet-configured rules.
      EOS
      default: false,
    },
  },
)