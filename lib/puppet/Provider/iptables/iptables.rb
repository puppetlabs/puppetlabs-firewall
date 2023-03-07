# frozen_string_literal: true
require_relative '../../../puppet_x/puppetlabs/firewall/utility'

# Implementation for the iptables type using the Resource API.
class Puppet::Provider::Iptables::Iptables #< Puppet::ResourceApi::SimpleProvider

  # Command to list all chains and rules
  $list_command = 'iptables-save'
  # Regex used to retrieve Chains
  $rules_regex = %r{(-A.*)[\n]}
  $chain_name_regex = %r{\n:(INPUT|FORWARD|OUTPUT|(?:\S+))}
  # Command to add a rule to a chain
  $create_command = 'iptables -I' # chain_name rule_num
  # Command to update a rule within a chain
  $update_command = 'iptables -R' # chain_name rule_num
  # Command to delete a rule from a chain
  $delete_command = 'iptables -D' # chain_name rule_num 
  # Commands for additional information
  # name: -m comment --comment
  # Number range 9000-9999 is reserved for unmanaged rules
  $unmanaged_rule_regex = %r{^9[0-9]{3}\s.*$}

  # Attribute resource map
  $resource_map = {
    name: '-m comment --comment',
    chain: '-A',
    proto: '-p',
    jump: '-j',
    sport: ['-m multiport --sports', '--sport'],
    dport: ['-m multiport --dports', '--dport'],
    source: '-s',
    destination: '-d',
  }
  $resource_map_full = {
    chain: '-A',
    burst: '--limit-burst',
    checksum_fill: '--checksum-fill',
    clamp_mss_to_pmtu: '--clamp-mss-to-pmtu',
    condition: '--condition',
    connlimit_above: '-m connlimit --connlimit-above',
    connlimit_mask: '--connlimit-mask',
    connmark: '-m connmark --mark',
    ctstate: '--ctstate',
    ctproto: '--ctproto',
    ctorigsrc: '--ctorigsrc',
    ctorigdst: '--ctorigdst',
    ctreplsrc: '--ctreplsrc',
    ctrepldst: '--ctrepldst',
    ctorigsrcport: '--ctorigsrcport',
    ctorigdstport: '--ctorigdstport',
    ctreplsrcport: '--ctreplsrcport',
    ctrepldstport: '--ctrepldstport',
    ctstatus: '--ctstatus',
    ctexpire: '--ctexpire',
    ctdir: '--ctdir',
    destination: '-d',
    dport: ['-m multiport --dports', '--dport'],
    dst_range: '--dst-range',
    dst_type: '--dst-type',
    gateway: '--gateway',
    gid: '--gid-owner',
    icmp: '-m icmp --icmp-type',
    iniface: '-i',
    ipsec_dir: '-m policy --dir',
    ipsec_policy: '--pol',
    ipset: '-m set --match-set',
    isfragment: '-f',
    jump: '-j',
    goto: '-g',
    length: '-m length --length',
    limit: '-m limit --limit',
    log_level: '--log-level',
    log_prefix: '--log-prefix',
    log_uid: '--log-uid',
    log_tcp_sequence: '--log-tcp-sequence',
    log_tcp_options: '--log-tcp-options',
    log_ip_options: '--log-ip-options',
    mac_source: ['-m mac --mac-source', '--mac-source'],
    mask: '--mask',
    match_mark: '-m mark --mark',
    mss: '-m tcpmss --mss',
    name: '-m comment --comment',
    nflog_group: '--nflog-group',
    nflog_prefix: '--nflog-prefix',
    nflog_range: '--nflog-range',
    nflog_size: '--nflog-size',
    nflog_threshold: '--nflog-threshold',
    outiface: '-o',
    pkttype: '-m pkttype --pkt-type',
    port: '-m multiport --ports', # deprecated
    proto: '-p',
    queue_num: '--queue-num',
    queue_bypass: '--queue-bypass',
    random_fully: '--random-fully',
    random: '--random',
    rdest: '--rdest',
    reap: '--reap',
    recent: '-m recent',
    reject: '--reject-with',
    rhitcount: '--hitcount',
    rname: '--name',
    rpfilter: '-m rpfilter',
    rseconds: '--seconds',
    rsource: '--rsource',
    rttl: '--rttl',
    set_dscp: '--set-dscp',
    set_dscp_class: '--set-dscp-class',
    set_mark: '--set-xmark',
    set_mss: '--set-mss',
    socket: '-m socket',
    source: '-s',
    sport: ['-m multiport --sports', '--sport'],
    src_range: '--src-range',
    src_type: '--src-type',
    stat_every: '--every',
    stat_mode: '-m statistic --mode',
    stat_packet: '--packet',
    stat_probability: '--probability',
    state: '-m state --state',
    string: '-m string --string',
    string_hex: '-m string --hex-string',
    string_algo: '--algo',
    string_from: '--from',
    string_to: '--to',
    table: '-t',
    tcp_flags: ['-m tcp --tcp-flags', '--tcp-flags'],
    todest: '--to-destination',
    toports: '--to-ports',
    tosource: '--to-source',
    to: '--to',
    uid: '--uid-owner',
    u32: ['-m u32 --u32', '--u32'],
    physdev_in: '--physdev-in',
    physdev_out: '--physdev-out',
    physdev_is_bridged: '--physdev-is-bridged',
    physdev_is_in: '--physdev-is-in',
    physdev_is_out: '--physdev-is-out',
    date_start: '--datestart',
    date_stop: '--datestop',
    time_start: '--timestart',
    time_stop: '--timestop',
    month_days: '--monthdays',
    week_days: '--weekdays',
    time_contiguous: '--contiguous',
    kernel_timezone: '--kerneltz',
    clusterip_new: '--new',
    clusterip_hashmode: '--hashmode',
    clusterip_clustermac: '--clustermac',
    clusterip_total_nodes: '--total-nodes',
    clusterip_local_node: '--local-node',
    clusterip_hash_init: '--hash-init',
    src_cc: '--source-country',
    dst_cc: '--destination-country',
    hashlimit_name: '--hashlimit-name',
    hashlimit_upto: '--hashlimit-upto',
    hashlimit_above: '--hashlimit-above',
    hashlimit_burst: '--hashlimit-burst',
    hashlimit_mode: '--hashlimit-mode',
    hashlimit_srcmask: '--hashlimit-srcmask',
    hashlimit_dstmask: '--hashlimit-dstmask',
    hashlimit_htable_size: '--hashlimit-htable-size',
    hashlimit_htable_max: '--hashlimit-htable-max',
    hashlimit_htable_expire: '--hashlimit-htable-expire',
    hashlimit_htable_gcinterval: '--hashlimit-htable-gcinterval',
    bytecode: '-m bpf --bytecode',
    ipvs: '-m ipvs --ipvs',
    zone: '--zone',
    helper: '--helper',
    cgroup: '-m cgroup --cgroup',
    notrack: '--notrack',
  }

  # These are known booleans that do not take a value, but we want to munge to true if they exist.
  $known_booleans = [
    :checksum_fill,
    :clamp_mss_to_pmtu,
    :isfragment,
    :log_uid,
    :log_tcp_sequence,
    :log_tcp_options,
    :log_ip_options,
    :random_fully,
    :random,
    :rdest,
    :reap,
    :rsource,
    :rttl,
    :socket,
    :physdev_is_bridged,
    :physdev_is_in,
    :physdev_is_out,
    :time_contiguous,
    :kernel_timezone,
    :clusterip_new,
    :queue_bypass,
    :ipvs,
    :notrack,
  ]

  # This is the order of resources as they appear in iptables-save output,
  # we need it to properly parse and apply rules, if the order of resource
  # changes between puppet runs, the changed rules will be re-applied again.
  # This order can be determined by going through iptables source code or just tweaking and trying manually
  $resource_list = [
    :table, :source, :destination, :iniface, :outiface,
    :physdev_in, :physdev_out, :physdev_is_bridged, :physdev_is_in, :physdev_is_out,
    :proto, :isfragment, :stat_mode, :stat_every, :stat_packet, :stat_probability,
    :src_range, :dst_range, :tcp_flags, :uid, :gid, :mac_source, :sport, :dport, :port,
    :src_type, :dst_type, :socket, :pkttype, :ipsec_dir, :ipsec_policy,
    :state, :ctstate, :ctproto, :ctorigsrc, :ctorigdst, :ctreplsrc, :ctrepldst,
    :ctorigsrcport, :ctorigdstport, :ctreplsrcport, :ctrepldstport, :ctstatus, :ctexpire, :ctdir,
    :icmp, :limit, :burst, :length, :recent, :rseconds, :reap,
    :rhitcount, :rttl, :rname, :mask, :rsource, :rdest, :ipset, :string, :string_hex, :string_algo,
    :string_from, :string_to, :jump, :goto, :clusterip_new, :clusterip_hashmode,
    :clusterip_clustermac, :clusterip_total_nodes, :clusterip_local_node, :clusterip_hash_init, :queue_num, :queue_bypass,
    :nflog_group, :nflog_prefix, :nflog_range, :nflog_size, :nflog_threshold, :clamp_mss_to_pmtu, :gateway,
    :set_mss, :set_dscp, :set_dscp_class, :todest, :tosource, :toports, :to, :checksum_fill, :random_fully, :random, :log_prefix,
    :log_level, :log_uid, :log_tcp_sequence, :log_tcp_options, :log_ip_options, :reject, :set_mark, :match_mark, :mss, :connlimit_above, :connlimit_mask, :connmark, :time_start, :time_stop,
    :month_days, :week_days, :date_start, :date_stop, :time_contiguous, :kernel_timezone,
    :src_cc, :dst_cc, :hashlimit_upto, :hashlimit_above, :hashlimit_name, :hashlimit_burst,
    :hashlimit_mode, :hashlimit_srcmask, :hashlimit_dstmask, :hashlimit_htable_size,
    :hashlimit_htable_max, :hashlimit_htable_expire, :hashlimit_htable_gcinterval, :bytecode, :ipvs, :zone, :helper, :cgroup, :rpfilter, :condition, :name, :notrack
  ]

  # Raw data is retrieved via `iptables -L` and then regexed to retrieve the different Chains and whether they have a set Policy
  def get(context)
    # Call the private method which returns the rules
    rules = Puppet::Provider::Iptables::Iptables.get_rules(context)
    # Verify the returned data
    Puppet::Provider::Iptables::Iptables.verify_get(context, rules)
    # Return array
    rules
  end

  # Retrieve the rules
  # Placed in it's own private method as the code is reused when determining order
  # Optional value lets you return a simplified set of data, used for determining order when adding/updating/deleting rules
  # @api.private
  def self.get_rules(context, basic = false)
    # Retrieve String containing all information
    iptables_list = Puppet::Provider.execute($list_command)
    # Create empty return array
    rules = []
    # Scan String to retrieve all Rules
    iptables_list.scan($rules_regex).each do |chain|
      if basic
        rules << Puppet::Provider::Iptables::Iptables.rule_to_name(context, chain)
      else
        rules << Puppet::Provider::Iptables::Iptables.rule_to_hash(context, chain)
      end
    end
    # Return array
    rules
  end

  # Verify that the information is correct
  # @api.private
  def self.verify_get(context, rules)
    # Verify that names are unique within each chain
    names = []
    rules.each do | rule |
      names << rule[:name]
    end
    if names.length != names.uniq.length
      raise "Duplicate names have been found within your Firewall Chain. This will prevent the module from working correctly and must be manually resolved."
    end
    # Verify that the current order of the retrieved puppet rules is correct
  end


  # Simplified version of 'self.rules_to_hash' meant to return name and chain only
  # @api.private
  def self.rule_to_name(context, rule)
    rule_hash = {}
    name_regex = Regexp.new($resource_map[:name] + '\s\\"(.*)[+"]')
    rule_hash[:name] = rule[0].scan(name_regex)[0][0]

    chain_regex = Regexp.new($resource_map[:chain] + '\s(\S+)')
    rule_hash[:chain] = rule[0].scan(chain_regex)[0][0]

    rule_hash
  end

  # Converts a given rule to a hash value
  # @api.private
  def self.rule_to_hash(context, rule)
    # loop through resource map
    rule_hash = {}
    rule_hash[:ensure] = 'present'
    # Add the ensure parameter first
    $resource_map.each do |key, value|
      # if resource is known_boolean
      if $known_booleans.include?(key)
        # check for existence, return true if it does
        if rule[0].scan(Regexp.new(value[0]))
          rule_hash[key] = true
        else
          rule_hash[key] = false
        end
      # if not
      else
        # check for existence, retrieve string that follows if it is
        # certain resources may need special rules
        case key
        when :name
          # When :name, return everything inside the double quote pair following the key value
          value_regex = Regexp.new(value + '\s\\"(.*)[+"]')
          key_value = rule[0].scan(value_regex)[0]
          rule_hash[key] = key_value[0] if key_value
        when :sport, :dport
          split_value_regex = value[0].split(/ /)
          negated_value_regex = [split_value_regex[0], split_value_regex[1], '!', split_value_regex[2]].join(' ')
          if rule[0].match(value[0])
            # First check against the multiport value, if found split and return as an array
            value_regex = Regexp.new(value[0] + '\s(\S+)')
            key_value = rule[0].scan(value_regex)[0]
            rule_hash[key] = key_value[0].split(/,/)
          elsif rule[0].match(negated_value_regex) # find negate multiport
            # Next check against a negated multiport value, if found split and return as an array with the first value negated
            value_regex = Regexp.new(negated_value_regex + '\s(\S+)')
            key_value = rule[0].scan(value_regex)[0]

            # Add '!' to the beginning of the first value to show it as negated
            split_value = key_value[0].split(/,/)
            split_value[0] = '! ' + split_value[0]
            rule_hash[key] = split_value
          elsif rule[0].match(value[1])
            # If no multi value matches, check against the regular value instead
            # Check for negation
            value_regex = Regexp.new('(?:(!)\s)?' + value[1] + '\s(\S+)')
            key_value = rule[0].scan(value_regex)[0]
            # If it has, combine the retrieved '!' with the actual value to make one string
            key_value[1] = [key_value[0], key_value[1]].join(" ") unless key_value[0].nil?
            rule_hash[key] = key_value[1]
          end
        when :proto, :source, :destination
          # Find if value has been negated
          if rule[0].match(value)
            value_regex = Regexp.new('(?:(!)\s)?' + value + '\s(\S+)')
            key_value = rule[0].scan(value_regex)[0]
            # If it has, combine the retrieved '!' with the actual value to make one string
            key_value[1] = [key_value[0], key_value[1]].join(" ") unless key_value[0].nil?
            rule_hash[key] = key_value[1] if key_value
          end
        else # :chain, :jump
          # Default return, retrieve first complete block following the key value
          if rule[0].match(value)
            value_regex = Regexp.new(value + '(?:\s(!)\s|\s)(\S+)')
            key_value = rule[0].scan(value_regex)[0]
            # If it has, combine the retrieved '!' with the actual value to make one string
            key_value[1] = [key_value[0], key_value[1]].join(" ") unless key_value[0].nil?
            rule_hash[key] = key_value[1] if key_value
          end
        end
      end
    end
    rule_hash
  end

  def set(context, changes)
    changes.each do |name, change|
      is = change[:is]
      should = change[:should]

      is = PuppetX::Firewall::Utility.create_absent(:name, name) if is.nil?
      should = PuppetX::Firewall::Utility.create_absent(:name, name) if should.nil?

      # Run static verification against both sets of values
      Puppet::Provider::Iptables::Iptables.verify_input(is, should)

      if is[:ensure].to_s == 'absent' && should[:ensure].to_s == 'present'
        context.creating(name) do
          create(context, name, should)
        end
      elsif is[:ensure].to_s == 'present' && should[:ensure].to_s == 'absent'
        context.deleting(name) do
          # Delete command requires additional context
          delete(context, name, is)
        end
      elsif is[:ensure].to_s == 'present'
        context.updating(name) do
          update(context, name, should)
        end
      end
    end
  end

  def create(context, name, should)
    context.notice("Creating Rule '#{name}' with #{should.inspect}")
    position = Puppet::Provider::Iptables::Iptables.insert_order(context, name, should[:chain])
    arguments = Puppet::Provider::Iptables::Iptables.hash_to_rule(context, name, should, position)
    Puppet::Provider.execute([$create_command, arguments].join(' '))
    PuppetX::Firewall::Utility.persist_iptables(context, name, 'IPv4')
    # TODO: Add code to handle Purge/Ignore/Ignore_Foreign
  end

  def update(context, name, should)
    context.notice("Updating Rule '#{name}' with #{should.inspect}")
    position = Puppet::Provider::Iptables::Iptables.insert_order(context, name, should[:chain])
    arguments = Puppet::Provider::Iptables::Iptables.hash_to_rule(context, name, should, position)
    Puppet::Provider.execute([$update_command, arguments].join(' '))
    PuppetX::Firewall::Utility.persist_iptables(context, name, 'IPv4')
    # TODO: Add code to handle Purge/Ignore/Ignore_Foreign
  end

  def delete(context, name, is)
    context.notice("Deleting Rule '#{name}'")
    position = Puppet::Provider::Iptables::Iptables.insert_order(context, name, is[:chain])
    arguments = [is[:chain], position.to_s].join(' ')
    Puppet::Provider.execute([$delete_command, arguments].join(' '))
    PuppetX::Firewall::Utility.persist_iptables(context, name, 'IPv4')
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
  def self.verify_input(is, should)
    # Verify that name does not start with 9000-9999
    raise 'Rule name cannot start with 9000-9999, as this range is reserved for unmanaged rules.' if should[:name].match($unmanaged_rule_regex)
    # Verify that if dport/sport is passed as an array, that only the first value is negated
    [:dport, :sport].each do | key |
      if should[key] && should[key].is_a?(Array)
        should[key].each_with_index do | value, index |
          raise "Only the first value in a '#{key.to_s}' array may be negated." if index >= 1 && value.match(%r{^!})
        end
      end
    end
  end

  # Find the correct position for our new rule in its chain
  # This has been lifted from the previous provider in order to maintain the logic between them
  # @api.private
  def self.insert_order(context, name, chain)
    rules = []
    Puppet::Provider::Iptables::Iptables.get_rules(context, true).each do | rule |
      if rule[:chain] == chain
        rules << rule[:name]
      end
    end

    # If no rules found, return 1
    return 1 if rules.empty?

    # Find if this is a new or eisting rule
    if rules.include? name
      # If the rule already exists, use it as the offset
      offset_rule = name
    else
      # If it doesn't add it to the list and find it's ordered location
      rules << name
      new_rule_location = rules.sort.uniq.index(name)
      offset_rule = if new_rule_location.zero?
                      # First and only rule
                      rules[0]
                    else
                      # This rule will come after other managed rules, so find the rule
                      # immediately preceeding it.
                      rules.sort.uniq[new_rule_location - 1]
                    end
    end
    # Count how many unmanaged rules are ahead of the target rule so we know
    # how much to add to the insert order
    unnamed_offset = rules[0..rules.index(offset_rule)].reduce(0) do |sum, rule|
      # This regex matches the names given to unmanaged rules (a number
      # 9000-9999 followed by an MD5 hash).
      sum + (rule.match($unmanaged_rule_regex) ? 1 : 0)
    end

    # We want our rule to come before unmanaged rules if it's not a 9-rule
    if offset_rule.match($unmanaged_rule_regex) && !name.match(%r{^9})
      unnamed_offset -= 1
    end

    # Insert our new or updated rule in the correct order of named rules, but
    # offset for unnamed rules.
    sorted_rules = rules.reject { |r| r.match($unmanaged_rule_regex) }.sort
    sorted_rules.index(name) + 1 + unnamed_offset
  end

  # Converts a given hash value to a command line argument
  # @api.private
  def self.hash_to_rule(context, name, rule, position)
    arguments = ' '
    # The chain and position must be added first
    arguments += [rule[:chain], position].join(' ')
    rule.each do |key, value|
      # if resource is known_boolean
      if $known_booleans.include?(key)
        # If value is true, append command to arguments
        arguments += $resource_map[key] if value
      else
        # check for existence, retrieve string that follows if it is
        # certain resources may need special rules
        case key
        when :chain, :ensure
          # Do nothing, :chain is handled seperately at the top and ensure is not part of the command
        when :name
          arguments += ' ' + [$resource_map[key], " \"#{rule[key]}\""].join('')
        when :sport, :dport
          if rule[key].is_a?(Array) && rule[key][0].match(%r{^!})
            # Negated Multiport
            split_comannd = $resource_map[key][0].split(/ /)
            negated_command = [split_comannd[0], split_comannd[1], '!', split_comannd[2]].join(' ')
            value = rule[key].join(',')[2..-1]
            arguments += ' ' + [negated_command, value].join(' ')
          elsif rule[key].is_a?(Array)
            # Standard Multiport
            arguments += ' ' + [$resource_map[key][0], rule[key].join(',')].join(' ')
          elsif rule[key].match(%r{^!})
            # Negated Standard
            # Add value after command, if negated add before command
            arguments += ' ' + ['!', $resource_map[key][1], rule[key][2..-1]].join(' ')
          else
            # Standard
            arguments += ' ' + [$resource_map[key][1], rule[key]].join(' ')
          end
        when :proto, :source, :destination
          # Add value after command, if negated add before command
          if rule[key].match(%r{^!})
            # Negated Standard
            # Add value after command, if negated add before command
            arguments += ' ' + ['!', $resource_map[key], rule[key][2..-1]].join(' ')
          else
            # Standard
            arguments += ' ' + [$resource_map[key], rule[key]].join(' ')
          end
        else # :jump
          # Add value after command
            arguments += ' ' + [$resource_map[key], rule[key]].join(' ')
        end
      end
    end
    arguments
  end
end
