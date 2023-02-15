# frozen_string_literal: true

# Implementation for the firewallchain type using the Resource API.
class Puppet::Provider::Firewallchain::Firewallchain #< Puppet::ResourceApi::SimpleProvider

  # Command to list all chains and rules
  $list_command = 'iptables -L'
  # Regex used to retrieve Chains
  $chain_regex = %r{Chain\s(INPUT|FORWARD|OUTPUT|(?:\S+))(?:\s\(policy\s(ACCEPT|DROP|QEUE|RETURN)\))?}
  # Command to create a chain
  $create_command = 'iptables -N'
  # Command to flush all rules from a chain, must be used before deleting
  $flush_command = 'iptables -F'
  # Command to delete a chain, cannot be used on inbuilt
  $delete_command = 'iptables -X'
  # Command to set chain policy, works on inbuilt chains only
  $policy_command = 'iptables -P'

  def set(context, changes)
    # require 'pry'; binding.pry;
    changes.each do |name, change|
      # require 'pry'; binding.pry;
      is = change[:is]
      should = change[:should]

      is = Puppet::Provider::Firewallchain::Firewallchain.create_absent(:name, name) if is.nil?
      should = Puppet::Provider::Firewallchain::Firewallchain.create_absent(:name, name) if should.nil?

      # Run static verification against both sets of values
      Puppet::Provider::Firewallchain::Firewallchain.verify(is, should)
      # require 'pry'; binding.pry;

      if is[:ensure].to_s == 'absent' && should[:ensure].to_s == 'present'
        context.creating(name) do
          create(context, name, should)
        end
      elsif is[:ensure].to_s == 'present' && should[:ensure].to_s == 'absent'
        context.deleting(name) do
          delete(context, name)
        end
      elsif is[:ensure].to_s == 'present'
        context.updating(name) do
          update(context, name, should)
        end
      end
    end
  end

  # Raw data is retrieved via `iptables -L` and then regexed to retrieve the different Chains and whether they have a set Policy
  def get(context)
    # Retriece String containing all information
    iptables_list = Puppet::Provider.execute($list_command)
    # Create empty return array
    chains = []
    # Scan String to retrieve all Chains and Policies
    iptables_list.scan($chain_regex).each do |chain|
      # If a policy was found add to array with Chain as hash
      if chain[1]
        chains << { name: chain[0], policy: chain[1].downcase, ensure: 'present' }
      # If not, simply add Chain
      else
        chains << { name: chain[0], ensure: 'present' }
      end
    end
    # Return array
    chains
  end

  def create(context, name, should)
    # require 'pry'; binding.pry;
    context.notice("Creating '#{name}' with #{should.inspect}")
    Puppet::Provider.execute([$create_command, name].join(' '))
    # TODO: Add code to handle Purge/Ignore/Ignore_Foreign
  end

  def update(context, name, should)
    # require 'pry'; binding.pry;
    # If an Inbuilt Chain, a policy is set in should and it differs from the current policy
    if ['INPUT', 'FORWARD', 'OUTPUT'].include?(should[:name]) && should.key?(:policy) && should[:policy] != is[:policy]
      context.notice("Updating '#{name}' with #{should.inspect}")
      Puppet::Provider.execute([$policy_command, name, should[:policy]].join(' '))
    end
    # TODO: Add code to handle Purge/Ignore/Ignore_Foreign
  end

  def delete(context, name)
    # require 'pry'; binding.pry;

    # Before we can delete a chain we must first flush it of any active rules
    context.notice("Flushing Chain '#{name}'")
    Puppet::Provider.execute([$flush_command, name].join(' '))

    # For Inbuilt chains we cannot delete them and so instead simply ensure they are reverted to the default policy
    if ["INPUT","FORWARD","OUTPUT"].include?(name)
      context.notice("Reverting Internal Chain '#{name}' to its default")
      Puppet::Provider.execute([$policy_command, name, 'ACCEPT'].join(' '))
    else
      context.notice("Deleting Chain '#{name}'")
      Puppet::Provider.execute([$delete_command, name].join(' '))
    end
    # TODO: Add code to handle Purge/Ignore/Ignore_Foreign
  end

  # @api private
  def self.create_absent(namevar, title)
    result = if title.is_a? Hash
                title.dup
              else
                { namevar => title }
              end
    result[:ensure] = 'absent'
    result
  end

  # Verify that the information is correct
  # @api.private
  def self.verify(is, should)
    # Verify that Policy is only passed for the inbuilt chains
    # require 'pry'; binding.pry;
    if !['INPUT', 'FORWARD', 'OUTPUT'].include?(should[:name]) && should.key?(:policy)
      fail "`policy` can only be set on Internal Chains. Setting for `#{should[:name]}` is invalid"
    end
    if ['INPUT', 'FORWARD', 'OUTPUT'].include?(should[:name]) && should[:ensure] == 'absent'
      warn "Warning: Inbuilt Chains may not be deleted. Chain `#{should[:name]}` will be flushed and have it's policy reverted to default."
    end
  end
end
