# frozen_string_literal: true

# This is a workaround for bug: #4248 whereby ruby files outside of the normal
# provider/type path do not load until pluginsync has occured on the puppet server
#
# In this case I'm trying the relative path first, then falling back to normal
# mechanisms. This should be fixed in future versions of puppet but it looks
# like we'll need to maintain this for some time perhaps.
$LOAD_PATH.unshift(File.join(File.dirname(__FILE__), '..', '..'))
require 'puppet/util/firewall'

Puppet::Type.newtype(:firewallchain) do
  include Puppet::Util::Firewall

  @doc = <<-PUPPETCODE
    @summary
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
  PUPPETCODE

  feature :iptables_chain, 'The provider provides iptables chain features.'
  feature :policy, 'Default policy (inbuilt chains only)'

  ensurable do
    defaultvalues
    defaultto :present
  end

  newparam(:name) do
    desc <<-PUPPETCODE
      The canonical name of the chain.

      For iptables the format must be {chain}:{table}:{protocol}.
    PUPPETCODE
    isnamevar

    validate do |value|
      if value !~ NAME_FORMAT
        raise ArgumentError, 'Inbuilt chains must be in the form {chain}:{table}:{protocol} where {table} is one of filter,' \
            ' nat, mangle, raw, rawpost, broute, security or empty (alias for filter), chain can be anything without colons' \
            ' or one of PREROUTING, POSTROUTING, BROUTING, INPUT, FORWARD, OUTPUT for the inbuilt chains, and {protocol} being' \
            " IPv4, IPv6, ethernet (ethernet bridging) got '#{value}' table:'#{Regexp.last_match(1)}' chain:'#{Regexp.last_match(2)}' protocol:'#{Regexp.last_match(3)}'"
      else
        chain = Regexp.last_match(1)
        table = Regexp.last_match(2)
        protocol = Regexp.last_match(3)
        case table
        when 'filter'
          if %r{^(PREROUTING|POSTROUTING|BROUTING)$}.match?(chain)
            raise ArgumentError, "INPUT, OUTPUT and FORWARD are the only inbuilt chains that can be used in table 'filter'"
          end
        when 'mangle'
          if chain =~ INTERNAL_CHAINS && chain == 'BROUTING'
            raise ArgumentError, "PREROUTING, POSTROUTING, INPUT, FORWARD and OUTPUT are the only inbuilt chains that can be used in table 'mangle'"
          end
        when 'nat'
          if %r{^(BROUTING|FORWARD)$}.match?(chain)
            raise ArgumentError, "PREROUTING, POSTROUTING, INPUT, and OUTPUT are the only inbuilt chains that can be used in table 'nat'"
          end
          if Gem::Version.new(Facter['kernelmajversion'].value.dup) < Gem::Version.new('3.7') && protocol =~ %r{^(IP(v6)?)?$}
            raise ArgumentError, "table nat isn't valid in IPv6. You must specify ':IPv4' as the name suffix"
          end
        when 'raw'
          if %r{^(POSTROUTING|BROUTING|INPUT|FORWARD)$}.match?(chain)
            raise ArgumentError, 'PREROUTING and OUTPUT are the only inbuilt chains in the table \'raw\''
          end
        when 'broute'
          if protocol != 'ethernet'
            raise ArgumentError, 'BROUTE is only valid with protocol \'ethernet\''
          end
          if %r{^PREROUTING|POSTROUTING|INPUT|FORWARD|OUTPUT$}.match?(chain)
            raise ArgumentError, 'BROUTING is the only inbuilt chain allowed on on table \'broute\''
          end
        when 'security'
          if %r{^(PREROUTING|POSTROUTING|BROUTING)$}.match?(chain)
            raise ArgumentError, "INPUT, OUTPUT and FORWARD are the only inbuilt chains that can be used in table 'security'"
          end
        end
        if chain == 'BROUTING' && (protocol != 'ethernet' || table != 'broute')
          raise ArgumentError, 'BROUTING is the only inbuilt chain allowed on on table \'BROUTE\' with protocol \'ethernet\' i.e. \'broute:BROUTING:enternet\''
        end
      end
    end
  end

  newproperty(:policy) do
    desc <<-PUPPETCODE
      This is the action to when the end of the chain is reached.
      It can only be set on inbuilt chains (INPUT, FORWARD, OUTPUT,
      PREROUTING, POSTROUTING) and can be one of:

      * accept - the packet is accepted
      * drop - the packet is dropped
      * queue - the packet is passed userspace
      * return - the packet is returned to calling (jump) queue
                 or the default of inbuilt chains
    PUPPETCODE
    newvalues(:accept, :drop, :queue, :return)
    defaultto do
      # ethernet chain have an ACCEPT default while other haven't got an
      # allowed value
      if @resource[:name] =~ %r{:ethernet$}
        :accept
      else
        nil
      end
    end
  end

  newparam(:purge, boolean: true) do
    desc <<-PUPPETCODE
      Purge unmanaged firewall rules in this chain
    PUPPETCODE
    newvalues(false, true)
    defaultto false
  end

  newparam(:ignore) do
    desc <<-PUPPETCODE
      Regex to perform on firewall rules to exempt unmanaged rules from purging (when enabled).
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
    PUPPETCODE

    validate do |value|
      unless value.is_a?(Array) || value.is_a?(String) || value == false
        devfail 'Ignore must be a string or an Array'
      end
    end
    munge do |patterns| # convert into an array of {Regex}es
      patterns = [patterns] if patterns.is_a?(String)
      patterns.map { |p| Regexp.new(p) }
    end
  end

  newparam(:ignore_foreign, boolean: true) do
    desc <<-PUPPETCODE
      Ignore rules that do not match the puppet title pattern "^\d+[[:graph:][:space:]]" when purging unmanaged firewall rules in this chain.
      This can be used to ignore rules that were not put in by puppet. Beware that nothing keeps other systems from configuring firewall rules with a comment that starts with digits, and is indistinguishable from puppet-configured rules.
    PUPPETCODE
    newvalues(false, true)
    defaultto false
  end

  # Classes would be a better abstraction, pending:
  # http://projects.puppetlabs.com/issues/19001
  autorequire(:package) do
    case value(:provider)
    when :iptables_chain
      ['iptables', 'iptables-persistent', 'iptables-services']
    else
      []
    end
  end

  autorequire(:service) do
    case value(:provider)
    when :iptables, :ip6tables
      ['firewalld', 'iptables', 'ip6tables', 'iptables-persistent', 'netfilter-persistent']
    else
      []
    end
  end

  validate do
    debug('[validate]')

    value(:name).match(NAME_FORMAT)
    chain = Regexp.last_match(1)
    table = Regexp.last_match(2)
    protocol = Regexp.last_match(3)

    # Check that we're not removing an internal chain
    if chain =~ INTERNAL_CHAINS && value(:ensure) == :absent
      raise 'Cannot remove in-built chains'
    end

    if value(:policy).nil? && protocol == 'ethernet'
      raise 'you must set a non-empty policy on all ethernet table chains'
    end

    # Check that we're not setting a policy on a user chain
    if chain !~ INTERNAL_CHAINS &&
       !value(:policy).nil? &&
       protocol != 'ethernet'

      raise "policy can only be set on in-built chains (with the exception of ethernet chains) (table:#{table} chain:#{chain} protocol:#{protocol})"
    end

    # no DROP policy on nat table
    if table == 'nat' &&
       value(:policy) == :drop

      raise 'The "nat" table is not intended for filtering, the use of DROP is therefore inhibited'
    end
  end

  def generate
    return [] unless purge?

    value(:name).match(NAME_FORMAT)
    chain = Regexp.last_match(1)
    table = Regexp.last_match(2)
    protocol = Regexp.last_match(3)

    provider = case protocol
               when 'IPv4'
                 :iptables
               when 'IPv6'
                 :ip6tables
               end

    # gather a list of all rules present on the system
    rules_resources = Puppet::Type.type(:firewall).instances

    # Keep only rules in this chain
    rules_resources.delete_if { |res| (res[:provider] != provider || res.provider.properties[:table].to_s != table || res.provider.properties[:chain] != chain) }

    # Remove rules which match our ignore filter
    rules_resources.delete_if { |res| value(:ignore).find_index { |f| res.provider.properties[:line].match(f) } } if value(:ignore)

    # Remove rules that were (presumably) not put in by puppet
    rules_resources.delete_if { |res| res.provider.properties[:name].match(%r{^(\d+)[[:graph:][:space:]]})[1].to_i >= 9000 } if value(:ignore_foreign) == :true

    # We mark all remaining rules for deletion, and then let the catalog override us on rules which should be present
    rules_resources.each { |res| res[:ensure] = :absent }

    rules_resources
  end
end
