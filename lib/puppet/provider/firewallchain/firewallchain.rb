# frozen_string_literal: true

require_relative '../../../puppet_x/puppetlabs/firewall/utility'

# Implementation for the firewallchain type using the Resource API.
class Puppet::Provider::Firewallchain::Firewallchain
  ###### GLOBAL VARIABLES ######

  # Command to list all chains and rules
  $list_command = {
    'IPv4' => 'iptables-save',
    'iptables' => 'iptables-save',
    'IPv6' => 'ip6tables-save',
    'ip6tables' => 'ip6tables-save'
  }
  # Regex used to divide output of$list_command between tables
  $table_regex = %r{(\*(?:nat|mangle|filter|raw|rawpost|broute|security)[^*]+)}
  # Array of all the supported iptables
  $supported_tables = ['nat', 'mangle', 'filter', 'raw', 'rawpost', 'broute', 'security']
  # Regex used to retrieve Chains
  $chain_regex = %r{\n:(INPUT|FORWARD|OUTPUT|(?:\S+))(?:\s(ACCEPT|DROP|QEUE|RETURN|PREROUTING|POSTROUTING))?}
  # Base commands for the protocols, including table affixes
  $base_command = {
    'IPv4' => 'iptables -t',
    'iptables' => 'iptables -t',
    'IPv6' => 'ip6tables -t',
    'ip6tables' => 'ip6tables -t',
  }
  # Command to create a chain
  $chain_create_command = '-N'
  # Command to flush all rules from a chain, must be used before deleting
  $chain_flush_command = '-F'
  # Command to delete a chain, cannot be used on inbuilt
  $chain_delete_command = '-X'
  # Command to set chain policy, works on inbuilt chains only
  $chain_policy_command = '-P'
  # Command to list specific table so it will generate necessary output for iptables-save
  # The retrieval of in-built chains may get confused by `iptables-save` tendency to not return table information
  # for tables that have not yet been interacted with.
  $table_list_command = '-L'
  # Check if the given chain name references a built in one
  $built_in_regex = %r{^(?:INPUT|OUTPUT|FORWARD|PREROUTING|POSTROUTING)$}

  ###### PUBLIC METHODS ######

  # Raw data is retrieved via `iptables-save` and then regexed to retrieve the different Chains and whether they have a set Policy
  def get(_context)
    # Create empty return array
    chains = []
    # Scan String to retrieve all Chains and Policies
    ['IPv4', 'IPv6'].each do |protocol|
      # Go through each supported table and retrieve its chains if it exists.
      $supported_tables.each do |table_name|
        cmd_output = Puppet::Provider.execute([$list_command[protocol], '-t', table_name].join(' '), failonfail: false)
        cmd_output.scan($chain_regex).each do |chain|
          # Create the base hash
          chain_hash = {
            name: "#{chain[0]}:#{table_name}:#{protocol}",
            purge: false,
            ignore_foreign: false,
            ensure: 'present'
          }
          # If a policy was found add to the hash
          chain_hash[:policy] = chain[1].downcase if chain[1]
          chains << chain_hash
        end
      end
    end
    # Return array
    chains
  end

  def set(context, changes)
    changes.each do |name, change|
      is = change[:is]
      should = change[:should]

      is = PuppetX::Firewall::Utility.create_absent(:name, name) if is.nil?
      should = PuppetX::Firewall::Utility.create_absent(:name, name) if should.nil?

      # Process the input and divide the name into it's relevant parts
      is, should = Puppet::Provider::Firewallchain::Firewallchain.process_input(is, should)
      # Run static verification against both sets of values
      Puppet::Provider::Firewallchain::Firewallchain.verify(is, should)

      if is[:ensure].to_s == 'absent' && should[:ensure].to_s == 'present'
        context.creating(name) do
          create(context, name, should)
        end
      elsif is[:ensure].to_s == 'present' && should[:ensure].to_s == 'absent'
        context.deleting(name) do
          delete(context, name, is)
        end
      elsif is[:ensure].to_s == 'present' && should[:ensure].to_s == 'present'
        context.updating(name) do
          update(context, name, should, is)
        end
      end
    end
  end

  def create(context, name, should)
    context.notice("Creating Chain '#{name}' with #{should.inspect}")
    # If a built-in chain is not present we assume that corresponding table has not been interacted with
    if $built_in_regex.match(should[:chain])
      Puppet::Provider.execute([$base_command[should[:protocol]], should[:table], $table_list_command].join(' '))
    else
      Puppet::Provider.execute([$base_command[should[:protocol]], should[:table], $chain_create_command, should[:chain]].join(' '))
    end
    PuppetX::Firewall::Utility.persist_iptables(context, name, should[:protocol])
  end

  def update(context, name, should, is)
    # Skip the update if not a inbuilt chain or if policy has not been updated
    return if !$built_in_regex.match(should[:chain]) ||
              ($built_in_regex.match(should[:chain]) && is[:policy] == should[:policy])

    context.notice("Updating Chain '#{name}' with #{should.inspect}")
    Puppet::Provider.execute([$base_command[should[:protocol]], should[:table], $chain_policy_command, should[:chain], should[:policy].upcase].join(' '))
    PuppetX::Firewall::Utility.persist_iptables(context, name, should[:protocol])
  end

  def delete(context, name, is)
    # Before we can delete a chain we must first flush it of any active rules
    context.notice("Flushing Chain '#{name}'")
    Puppet::Provider.execute([$base_command[is[:protocol]], is[:table], $chain_flush_command, is[:chain]].join(' '))

    # For Inbuilt chains we cannot delete them and so instead simply ensure they are reverted to the default policy
    if $built_in_regex.match(is[:chain])
      context.notice("Reverting Internal Chain '#{name}' to its default")
      Puppet::Provider.execute([$base_command[is[:protocol]], is[:table], $chain_policy_command, is[:chain], 'ACCEPT'].join(' '))
    else
      context.notice("Deleting Chain '#{name}'")
      Puppet::Provider.execute([$base_command[is[:protocol]], is[:table], $chain_delete_command, is[:chain]].join(' '))
    end
    PuppetX::Firewall::Utility.persist_iptables(context, name, is[:protocol])
  end

  # Custom insync method
  def insync?(context, _name, property_name, _is_hash, _should_hash)
    context.debug("Checking whether '#{property_name}' is out of sync")

    case property_name
    when :purge, :ignore, :ignore_foreign
      # Suppres any update notifications for the purge/ignore(_foreign) values
      # They are used in the generate method which is ran prior to this point and have no
      # bearing on it's actual state.
      true
    else
      nil
    end
  end

  ###### PRIVATE METHODS ######

  # Process the information so that it can be correctly applied
  # @api private
  def self.process_input(is, should)
    # Split the name into it's relevant parts
    is[:name] = is[:title] if is[:name].nil?
    is[:chain], is[:table], is[:protocol] = is[:name].split(':')
    should[:name] = should[:title] if should[:name].nil?
    should[:chain], should[:table], should[:protocol] = should[:name].split(':')

    # If an in-built chain, ensure it is assigned a policy
    is[:policy] = 'accept' if $built_in_regex.match(is[:chain]) && is[:policy].nil?
    # For the same reason assign it the default policy as an intended state if it does not have one
    should[:policy] = 'accept' if $built_in_regex.match(should[:chain]) && should[:policy].nil?

    [is, should]
  end

  # Verify that the information is correct
  # @api private
  def self.verify(_is, should)
    # Verify that no incorrect chain names are passed
    case should[:table]
    when 'filter'
      raise ArgumentError, 'INPUT, OUTPUT and FORWARD are the only inbuilt chains that can be used in table \'filter\'' if %r{^(PREROUTING|POSTROUTING|BROUTING)$}.match?(should[:chain])
    when 'mangle'
      raise ArgumentError, 'PREROUTING, POSTROUTING, INPUT, FORWARD and OUTPUT are the only inbuilt chains that can be used in table \'mangle\'' if %r{^(BROUTING)$}.match?(should[:chain])
    when 'nat'
      raise ArgumentError, 'PREROUTING, POSTROUTING, INPUT, and OUTPUT are the only inbuilt chains that can be used in table \'nat\'' if %r{^(BROUTING|FORWARD)$}.match?(should[:chain])
    when 'raw'
      raise ArgumentError, 'PREROUTING and OUTPUT are the only inbuilt chains in the table \'raw\'' if %r{^(POSTROUTING|BROUTING|INPUT|FORWARD)$}.match?(should[:chain])
    when 'broute'
      raise ArgumentError, 'BROUTE is only valid with protocol \'ethernet\'' if should[:protocol] != 'ethernet'
      raise ArgumentError, 'BROUTING is the only inbuilt chain allowed on on table \'broute\'' if %r{^PREROUTING|POSTROUTING|INPUT|FORWARD|OUTPUT$}.match?(should[:chain])
    when 'security'
      raise ArgumentError, 'INPUT, OUTPUT and FORWARD are the only inbuilt chains that can be used in table \'security\'' if %r{^(PREROUTING|POSTROUTING|BROUTING)$}.match?(should[:chain])
    end

    # Verify that Policy is only passed for the inbuilt chains
    raise ArgumentError, "'policy' can only be set on Internal Chains. Setting for '#{should[:name]}' is invalid" if !$built_in_regex.match(should[:chain]) && should.key?(:policy)

    # Warn that inbuilt chains will be flushed, not deleted
    warn "Warning: Inbuilt Chains may not be deleted. Chain `#{should[:name]}` will be flushed and have it's policy reverted to default." if $built_in_regex.match(should[:chain]) &&
                                                                                                                                             should[:ensure] == 'absent'
  end

  # Customer generate method called by the resource_api
  # Finds and returns all unmanaged rules on the chain that are not set to be ignored
  def generate(_context, title, _is, should)
    # Unless purge is true, return an empty array
    return [] unless should[:purge]

    # gather a list of all rules present on the system
    rules_resources = Puppet::Type.type(:firewall).instances

    # Retrieve information from the title
    name, table, protocol = title.split(':')

    # Keep only rules in this chain
    rules_resources.delete_if do |resource|
      resource.rsapi_current_state[:chain] != name || resource.rsapi_current_state[:table] != table || resource.rsapi_current_state[:protocol] != protocol
    end

    # Remove rules which match our ignore filter
    # Ensure ignore value is wrapped as an array to simplify the code
    should[:ignore] = [should[:ignore]] if should[:ignore].is_a?(String)
    rules_resources.delete_if { |resource| should[:ignore].find_index { |ignore| resource.rsapi_current_state[:line].match(ignore) } } if should[:ignore]

    # Remove rules that were (presumably) not put in by puppet
    rules_resources.delete_if { |resource| resource.rsapi_current_state[:name].match(%r{^(\d+)[[:graph:][:space:]]})[1].to_i >= 9000 } if should[:ignore_foreign]

    # We mark all remaining rules for deletion, and then let the catalog override us on rules which should be present
    # We also ensure that the generate rules have the correct protocol to avoid issues with our validation
    rules_resources.each do |resource|
      resource[:ensure] = :absent
      resource[:protocol] = protocol
    end

    rules_resources
  end
end
