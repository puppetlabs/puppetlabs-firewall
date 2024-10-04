# frozen_string_literal: true

require_relative '../../../puppet_x/puppetlabs/firewall/utility'

# Implementation for the iptables type using the Resource API.
class Puppet::Provider::Firewall::Firewall
  ###### GLOBAL VARIABLES ######

  # Command to list all chains and rules
  # $list_command = 'iptables-save'
  $list_command = {
    'IPv4' => 'iptables-save',
    'iptables' => 'iptables-save',
    'IPv6' => 'ip6tables-save',
    'ip6tables' => 'ip6tables-save'
  }
  # Regex used to divide output of$list_command between tables
  $table_regex = %r{(\*(?:nat|mangle|filter|raw|rawpost|broute|security)[^*]+)}
  # Regex used to retrieve table name
  $table_name_regex = %r{^\*(nat|mangle|filter|raw|rawpost|broute|security)}
  # Regex used to retrieve Rules
  $rules_regex = %r{(-A.*)\n}
  # Base command
  $base_command = {
    'IPv4' => 'iptables -t',
    'iptables' => 'iptables -t',
    'IPv6' => 'ip6tables -t',
    'ip6tables' => 'ip6tables -t'
  }
  # Command to add a rule to a chain
  $rule_create_command = '-I' # chain_name rule_num
  # Command to update a rule within a chain
  $rule_update_command = '-R' # chain_name rule_num
  # Command to delete a rule from a chain
  $rule_delete_command = '-D' # chain_name rule_num
  # Number range 9000-9999 is reserved for unmanaged rules
  $unmanaged_rule_regex = %r{^9[0-9]{3}\s.*$}

  # Attribute resource map
  # Map is ordered as the attributes appear in the iptables-save/ip6tables-save output
  $resource_map = {
    chain: '-A',
    source: '-s',
    destination: '-d',
    iniface: '-i',
    outiface: '-o',
    physdev_in: '--physdev-in',
    physdev_out: '--physdev-out',
    physdev_is_bridged: '--physdev-is-bridged',
    physdev_is_in: '--physdev-is-in',
    physdev_is_out: '--physdev-is-out',
    proto: '-p',
    isfragment: '-f',
    isfirstfrag: '-m frag --fragid 0 --fragfirst',
    ishasmorefrags: '-m frag --fragid 0 --fragmore',
    islastfrag: '-m frag --fragid 0 --fraglast',
    stat_mode: '-m statistic --mode',
    stat_every: '--every',
    stat_packet: '--packet',
    stat_probability: '--probability',
    src_range: '--src-range',
    dst_range: '--dst-range',
    tcp_option: '--tcp-option',
    tcp_flags: '--tcp-flags',
    uid: '--uid-owner',
    gid: '--gid-owner',
    mac_source: '--mac-source',
    sport: ['-m multiport --sports', '--sport'],
    dport: ['-m multiport --dports', '--dport'],
    src_type: '-m addrtype --src-type',
    dst_type: '-m addrtype --dst-type',
    socket: '-m socket',
    pkttype: '--pkt-type',
    ipsec_dir: '--dir',
    ipsec_policy: '--pol',
    state: '--state',
    ctmask: '--ctmask',
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
    hop_limit: '--hl-eq',
    icmp: ['-m icmp --icmp-type', '-m icmp6 --icmpv6-type'],
    limit: '--limit',
    burst: '--limit-burst',
    length: '-m length --length',
    recent: '-m recent',
    rseconds: '--seconds',
    reap: '--reap',
    rhitcount: '--hitcount',
    rttl: '--rttl',
    rname: '--name',
    mask: '--mask',
    rsource: '--rsource',
    rdest: '--rdest',
    ipset: '-m set --match-set',
    string: '--string',
    string_hex: '--hex-string',
    string_algo: '--algo',
    string_from: '--from',
    string_to: '--to',
    jump: '-j',
    goto: '-g',
    clusterip_new: '--new',
    clusterip_hashmode: '--hashmode',
    clusterip_clustermac: '--clustermac',
    clusterip_total_nodes: '--total-nodes',
    clusterip_local_node: '--local-node',
    clusterip_hash_init: '--hash-init',
    queue_num: '--queue-num',
    queue_bypass: '--queue-bypass',
    nflog_group: '--nflog-group',
    nflog_prefix: '--nflog-prefix',
    nflog_range: '--nflog-range',
    nflog_size: '--nflog-size',
    nflog_threshold: '--nflog-threshold',
    nfmask: '--nfmask',
    gateway: '--gateway',
    clamp_mss_to_pmtu: '--clamp-mss-to-pmtu',
    set_mss: '--set-mss',
    set_dscp: '--set-dscp',
    set_dscp_class: '--set-dscp-class',
    todest: '--to-destination',
    tosource: '--to-source',
    toports: '--to-ports',
    to: '--to',
    checksum_fill: '--checksum-fill',
    random_fully: '--random-fully',
    random: '--random',
    log_prefix: '--log-prefix',
    log_level: '--log-level',
    log_uid: '--log-uid',
    log_tcp_sequence: '--log-tcp-sequence',
    log_tcp_options: '--log-tcp-options',
    log_ip_options: '--log-ip-options',
    reject: '--reject-with',
    restore_mark: '--restore-mark',
    set_mark: '--set-xmark',
    match_mark: '-m mark --mark',
    mss: '-m tcpmss --mss',
    connlimit_upto: '--connlimit-upto',
    connlimit_above: '--connlimit-above',
    connlimit_mask: '--connlimit-mask',
    connmark: '-m connmark --mark',
    time_start: '--timestart',
    time_stop: '--timestop',
    month_days: '--monthdays',
    week_days: '--weekdays',
    date_start: '--datestart',
    date_stop: '--datestop',
    time_contiguous: '--contiguous',
    kernel_timezone: '--kerneltz',
    u32: '--u32',
    src_cc: '--source-country',
    dst_cc: '--destination-country',
    hashlimit_upto: '--hashlimit-upto',
    hashlimit_above: '--hashlimit-above',
    hashlimit_name: '--hashlimit-name',
    hashlimit_burst: '--hashlimit-burst',
    hashlimit_mode: '--hashlimit-mode',
    hashlimit_srcmask: '--hashlimit-srcmask',
    hashlimit_dstmask: '--hashlimit-dstmask',
    hashlimit_htable_size: '--hashlimit-htable-size',
    hashlimit_htable_max: '--hashlimit-htable-max',
    hashlimit_htable_expire: '--hashlimit-htable-expire',
    hashlimit_htable_gcinterval: '--hashlimit-htable-gcinterval',
    bytecode: '-m bpf --bytecode',
    ipvs: '--ipvs',
    cgroup: '--cgroup',
    rpfilter: '-m rpfilter',
    condition: '--condition',
    name: '-m comment --comment',
    notrack: '--notrack',
    helper: '--helper',
    zone: '--zone'
  }

  # These are known booleans that do not take a value.
  $known_booleans = [
    :checksum_fill, :clamp_mss_to_pmtu, :isfragment, :ishasmorefrags, :islastfrag, :isfirstfrag,
    :log_uid, :log_tcp_sequence, :log_tcp_options, :log_ip_options, :random_fully, :random,
    :rdest, :reap, :rsource, :rttl, :socket, :physdev_is_bridged, :physdev_is_in, :physdev_is_out,
    :time_contiguous, :kernel_timezone, :clusterip_new, :queue_bypass, :ipvs, :notrack, :restore_mark
  ]

  # Properties that use "-m <ipt module name>" (with the potential to have multiple
  # arguments against the same IPT module) must be in this hash. The keys in this
  # hash are the IPT module names, with the values being an array of the respective
  # supported arguments for this IPT module.
  #
  # ** IPT Module arguments must be in order as they would appear in iptables-save **
  #
  # Exceptions:
  #             => multiport: (For some reason, the multiport arguments can't be)
  #                specified within the same "-m multiport", but works in seperate
  #                ones.
  #             => addrtype: Each instance of src_type/dst_type requires it's own preface
  #
  @module_to_argument_mapping = {
    physdev: [:physdev_in, :physdev_out, :physdev_is_bridged, :physdev_is_in, :physdev_is_out],
    iprange: [:src_range, :dst_range],
    tcp: [:tcp_option, :tcp_flags],
    owner: [:uid, :gid],
    mac: [:mac_source],
    policy: [:ipsec_dir, :ipsec_policy],
    condition: [:condition],
    pkttype: [:pkttype],
    state: [:state],
    conntrack: [:ctstate, :ctproto, :ctorigsrc, :ctorigdst, :ctreplsrc, :ctrepldst,
                :ctorigsrcport, :ctorigdstport, :ctreplsrcport, :ctrepldstport, :ctstatus, :ctexpire, :ctdir],
    hl: [:hop_limit],
    limit: [:limit, :burst],
    string: [:string, :string_hex, :string_algo, :string_from, :string_to],
    connlimit: [:connlimit_upto, :connlimit_above, :connlimit_mask],
    time: [:time_start, :time_stop, :month_days, :week_days, :date_start, :date_stop, :time_contiguous, :kernel_timezone],
    u32: [:u32],
    geoip: [:src_cc, :dst_cc],
    hashlimit: [:hashlimit_upto, :hashlimit_above, :hashlimit_name, :hashlimit_burst, :hashlimit_mode, :hashlimit_srcmask, :hashlimit_dstmask,
                :hashlimit_htable_size, :hashlimit_htable_max, :hashlimit_htable_expire, :hashlimit_htable_gcinterval],
    ipvs: [:ipvs],
    cgroup: [:cgroup]
  }

  # This is the order of resources as they appear in ip(6)tables-save output,
  # it is used in order to ensure that the rules are applied in the correct order.
  # This order can be determined by going through iptables source code or just tweaking and trying manually
  $resource_list = [
    :source, :destination, :iniface, :outiface,
    :physdev_in, :physdev_out, :physdev_is_bridged, :physdev_is_in, :physdev_is_out,
    :proto, :isfragment, :ishasmorefrags, :islastfrag, :isfirstfrag,
    :stat_mode, :stat_every, :stat_packet, :stat_probability,
    :src_range, :dst_range, :tcp_option, :tcp_flags, :uid, :gid, :mac_source, :sport, :dport,
    :src_type, :dst_type, :socket, :pkttype, :ipsec_dir, :ipsec_policy,
    :state, :ctstate, :ctproto, :ctorigsrc, :ctorigdst, :ctreplsrc, :ctrepldst,
    :ctorigsrcport, :ctorigdstport, :ctreplsrcport, :ctrepldstport, :ctstatus, :ctexpire, :ctdir,
    :hop_limit, :icmp, :limit, :burst, :length, :recent, :rseconds, :reap,
    :rhitcount, :rttl, :rname, :mask, :rsource, :rdest, :ipset, :string, :string_hex, :string_algo,
    :string_from, :string_to, :jump, :goto, :clusterip_new, :clusterip_hashmode,
    :clusterip_clustermac, :clusterip_total_nodes, :clusterip_local_node, :clusterip_hash_init, :queue_num, :queue_bypass,
    :nflog_group, :nflog_prefix, :nflog_range, :nflog_size, :nflog_threshold, :clamp_mss_to_pmtu, :gateway,
    :set_mss, :set_dscp, :set_dscp_class, :todest, :tosource, :toports, :to, :checksum_fill, :random_fully, :random, :log_prefix,
    :log_level, :log_uid, :log_tcp_sequence, :log_tcp_options, :log_ip_options, :reject, :set_mark, :match_mark, :restore_mark, :nfmask, :ctmask, :mss,
    :connlimit_upto, :connlimit_above, :connlimit_mask, :connmark,
    :time_start, :time_stop, :month_days, :week_days, :date_start, :date_stop, :time_contiguous, :kernel_timezone,
    :u32, :src_cc, :dst_cc, :hashlimit_upto, :hashlimit_above, :hashlimit_name, :hashlimit_burst,
    :hashlimit_mode, :hashlimit_srcmask, :hashlimit_dstmask, :hashlimit_htable_size,
    :hashlimit_htable_max, :hashlimit_htable_expire, :hashlimit_htable_gcinterval,
    :bytecode, :ipvs, :helper, :zone, :cgroup, :rpfilter, :condition, :name, :notrack
  ]

  ###### PUBLIC METHODS ######

  def get(context)
    # Call the private method which returns the rules
    # The method is seperated out in this way as it is re-used later in the code
    rules = Puppet::Provider::Firewall::Firewall.get_rules(context, false)
    # Verify the returned data
    Puppet::Provider::Firewall::Firewall.validate_get(context, rules)
    # Return array
    rules
  end

  def set(context, changes)
    changes.each do |name, change|
      is = change[:is]
      should = change[:should]

      is = PuppetX::Firewall::Utility.create_absent(:name, name) if is.nil?
      should = PuppetX::Firewall::Utility.create_absent(:name, name) if should.nil?

      # Run static verification against both sets of values
      Puppet::Provider::Firewall::Firewall.validate_input(is, should)
      # Process the intended values so that they are inputed as they should be
      should = Puppet::Provider::Firewall::Firewall.process_input(should)

      if is[:ensure].to_s == 'absent' && should[:ensure].to_s == 'present'
        context.creating(name) do
          create(context, name, should)
        end
      elsif is[:ensure].to_s == 'present' && should[:ensure].to_s == 'absent'
        context.deleting(name) do
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
    position = Puppet::Provider::Firewall::Firewall.insert_order(context, name, should[:chain], should[:table], should[:protocol])
    arguments = Puppet::Provider::Firewall::Firewall.hash_to_rule(context, name, should)
    Puppet::Provider.execute([$base_command[should[:protocol]], should[:table], $rule_create_command, should[:chain], position, arguments].join(' '))
    PuppetX::Firewall::Utility.persist_iptables(context, name, should[:protocol])
  end

  def update(context, name, should)
    context.notice("Updating Rule '#{name}' with #{should.inspect}")
    position = Puppet::Provider::Firewall::Firewall.insert_order(context, name, should[:chain], should[:table], should[:protocol])
    arguments = Puppet::Provider::Firewall::Firewall.hash_to_rule(context, name, should)
    Puppet::Provider.execute([$base_command[should[:protocol]], should[:table], $rule_update_command, should[:chain], position, arguments].join(' '))
    PuppetX::Firewall::Utility.persist_iptables(context, name, should[:protocol])
  end

  def delete(context, name, is)
    context.notice("Deleting Rule '#{name}'")
    # When deleting we use the retrieved iptables-save append command as a base
    # We do this to ensure accuracy when removing non-standard (i.e. uncommented) rules via the firewallchain purge function
    arguments = is[:line].gsub(%r{^-A}, $rule_delete_command)
    Puppet::Provider.execute([$base_command[is[:protocol]], is[:table], arguments].join(' '))
    PuppetX::Firewall::Utility.persist_iptables(context, name, is[:protocol])
  end

  # Custom insync method
  # Needed for uid and gid
  def insync?(context, _name, property_name, is_hash, should_hash)
    context.debug("Checking whether '#{property_name}' is out of sync")

    # If either value is nil, no custom logic is required
    return nil if is_hash[property_name].nil? || should_hash[property_name].nil?

    case property_name
    when :protocol
      is = is_hash[property_name]
      should = should_hash[property_name]

      # Ensure the should value accurately matches the is
      should = 'IPv4' if should == 'iptables'
      should = 'IPv6' if should == 'ip6tables'

      is == should
    when :source, :destination
      # Ensure source/destination has it's valid mask before you compare it
      is_hash[property_name] == PuppetX::Firewall::Utility.host_to_mask(should_hash[property_name], should_hash[:protocol])
    when :tcp_option, :ctproto, :hop_limit
      # Ensure that the values are compared as strings
      is_hash[property_name] == should_hash[property_name].to_s
    when :tcp_flags
      # Custom logic to account for `ALL` being returned as `FIN,SYN,RST,PSH,ACK,URG`
      is = is_hash[property_name].split
      should = should_hash[property_name].split

      is = is.map { |x| (x == 'FIN,SYN,RST,PSH,ACK,URG') ? 'ALL' : x }
      should = should.map { |x| (x == 'FIN,SYN,RST,PSH,ACK,URG') ? 'ALL' : x }

      is.join(' ') == should.join(' ')
    when :uid, :gid
      require 'etc'
      # The following code allow us to take into consideration unix mappings
      # between string usernames and UIDs (integers). We also need to ignore
      # spaces as they are irrelevant with respect to rule sync.

      # Remove whitespace
      is = is_hash[property_name].to_s.gsub(%r{\s+}, '')
      should = should_hash[property_name].to_s.gsub(%r{\s+}, '')

      # Keep track of negation, but remove the '!'
      is_negate = ''
      should_negate = ''
      if is.start_with?('!')
        is = is.gsub(%r{^!}, '')
        is_negate = '!'
      end
      if should.start_with?('!')
        should = should.gsub(%r{^!}, '')
        should_negate = '!'
      end

      # If 'is' or 'should' contain anything other than digits or digit range,
      # we assume that we have to do a lookup to convert to UID
      is = Etc.getpwnam(is).uid unless is[%r{[0-9]+(-[0-9]+)?}] == is
      should = Etc.getpwnam(should).uid unless should[%r{[0-9]+(-[0-9]+)?}] == should

      "#{is_negate}#{is}" == "#{should_negate}#{should}"
    when :mac_source, :jump
      # Value of mac_source/jump may be downcased or upcased when returned depending on the OS
      is_hash[property_name].casecmp(should_hash[property_name]).zero?
    when :icmp
      # Ensure that the values are compared to each other as icmp code numbers
      is = PuppetX::Firewall::Utility.icmp_name_to_number(is_hash[property_name], is_hash[:protocol])
      should = PuppetX::Firewall::Utility.icmp_name_to_number(should_hash[property_name], should_hash[:protocol])
      is == should
    when :log_level
      # Ensure that the values are compared to each other as log level numbers
      is = PuppetX::Firewall::Utility.log_level_name_to_number(is_hash[property_name])
      should = PuppetX::Firewall::Utility.log_level_name_to_number(should_hash[property_name])
      is == should
    when :set_mark
      # Ensure that the values are compared to eachother in hexidecimal format
      is = PuppetX::Firewall::Utility.mark_mask_to_hex(is_hash[property_name])
      should = PuppetX::Firewall::Utility.mark_mask_to_hex(should_hash[property_name])
      is == should
    when :match_mark, :connmark
      # Ensure that the values are compared to eachother in hexidecimal format
      is = PuppetX::Firewall::Utility.mark_to_hex(is_hash[property_name])
      should = PuppetX::Firewall::Utility.mark_to_hex(should_hash[property_name])
      is == should
    when :time_start, :time_stop
      # Ensure the values are compared in full `00:00:00` format
      is = is_hash[property_name]
      should = should_hash[property_name]

      should = "0#{should}" if %r{^([0-9]):}.match?(should)
      should = "#{should}:00" if %r{^([0-9]|0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$}.match?(should)

      is == should
    when :dport, :sport, :state, :ctstate, :ctstatus
      is = is_hash[property_name]
      should = should_hash[property_name]

      # Unique logic is only needed when both values are arrays
      return nil unless is.is_a?(Array) && should.is_a?(Array)

      # Ensure values are sorted
      # Ensure any negation includes only the first value
      is_negated = true if %r{^!\s}.match?(is[0].to_s)
      is.each_with_index do |_value, _index|
        is = is.map { |value| value.to_s.tr('! ', '') }.sort
      end
      is[0] = ['!', is[0]].join(' ') if is_negated

      should_negated = true if %r{^!\s}.match?(should[0].to_s)
      should.each_with_index do |_value, _index|
        should = should.map { |value| value.to_s.tr('! ', '') }.sort
        # Port range can be passed as `-` but will always be set/returned as `:`
        ports = [:dport, :sport]
        should = should.map { |value| value.to_s.tr('-', ':') }.sort if ports.include?(property_name)
      end
      should[0] = ['!', should[0]].join(' ') if should_negated

      is == should
    when :string_hex
      # Compare the values with any whitespace removed
      is = is_hash[property_name].to_s.gsub(%r{\s+}, '')
      should = should_hash[property_name].to_s.gsub(%r{\s+}, '')

      is == should
    else
      # Ensure that if both values are arrays, that they are sorted prior to comparison
      return nil unless is_hash[property_name].is_a?(Array) && should_hash[property_name].is_a?(Array)

      is_hash[property_name].sort == should_hash[property_name].sort
    end
  end

  ###### PRIVATE METHODS ######
  ###### GET ######

  # Retrieve the rules
  # Optional values lets you return a simplified set of data, used for determining order when adding/updating/deleting rules,
  #   while also allowing for the protocols used to retrieve the rules to be limited.
  # @api private
  def self.get_rules(context, basic, protocols = ['IPv4', 'IPv6'])
    # Create empty return array
    rules = []
    counter = 1
    # For each protocol
    protocols.each do |protocol|
      # Retrieve String containing all information
      iptables_list = Puppet::Provider.execute($list_command[protocol])
      # Scan String to retrieve all Rules
      iptables_list.scan($table_regex).each do |table|
        table_name = table[0].scan($table_name_regex)[0][0]
        table[0].scan($rules_regex).each do |rule|
          raw_rules = if basic
                        Puppet::Provider::Firewall::Firewall.rule_to_name(context, rule[0], table_name, protocol)
                      else
                        Puppet::Provider::Firewall::Firewall.rule_to_hash(context, rule[0], table_name, protocol)
                      end
          # Process the returned values so that it is correct for our purposes
          rules << Puppet::Provider::Firewall::Firewall.process_get(context, raw_rules, rule[0], counter)
          counter += 1
        end
      end
      # Return array
    end
    rules
  end

  # Simplified version of 'self.rules_to_hash' meant to return name, chain and table only
  # @api private
  def self.rule_to_name(_context, rule, table_name, protocol)
    rule_hash = {}
    rule_hash[:ensure] = 'present'
    rule_hash[:table] = table_name
    rule_hash[:protocol] = protocol

    name_regex = Regexp.new("#{$resource_map[:name]}\\s(?:\"([^\"]*)|([^\"\\s]*))")
    name_value = rule.scan(name_regex)[0]
    # Combine the returned values and remove and trailing or leading whitespace
    rule_hash[:name] = [name_value[0], name_value[1]].join(' ').strip if name_value

    chain_regex = Regexp.new("#{$resource_map[:chain]}\\s(\\S+)")
    rule_hash[:chain] = rule.scan(chain_regex)[0][0]

    rule_hash
  end

  # Converts a given rule to a hash value
  # @api private
  def self.rule_to_hash(_context, rule, table_name, protocol)
    # loop through resource map
    rule_hash = {}
    rule_hash[:ensure] = 'present'
    rule_hash[:table] = table_name
    rule_hash[:protocol] = protocol
    rule_hash[:line] = rule
    # Add the ensure parameter first
    $resource_map.each do |key, value|
      if $known_booleans.include?(key)
        # check for flag with regex, add a space/line end to ensure accuracy with the more simplistic flags; i.e. `-f`, `--random`
        rule_hash[key] = if rule.match(Regexp.new("#{value}(\\s|$)"))
                           true
                         else
                           false
                         end
        next
      end

      case key
      when :name, :string, :string_hex, :bytecode, :u32, :nflog_prefix, :log_prefix
        # When :name/:string/:string_hex/:bytecode, return everything inside the double quote pair following the key value
        # When only a single word comment is returned no quotes are given, so we must check for this as well
        # First find if flag is present, add a space to ensure accuracy with the more simplistic flags; i.e. `-i`
        if rule.match(Regexp.new("#{value}\\s"))
          value_regex = Regexp.new("(?:(!\\s))?#{value}\\s(?:\"([^\"]*)|([^\"\\s]*))")
          key_value = rule.scan(value_regex)[0]
          # Combine the returned values and remove and trailing or leading whitespace
          key_value[1] = [key_value[0], key_value[1], key_value[2]].join
          rule_hash[key] = key_value[1] if key_value[1]
        end
      when :sport, :dport
        split_value_regex = value[0].split(%r{ })
        negated_multi_regex = [split_value_regex[0], split_value_regex[1], '!', split_value_regex[2]].join(' ')
        if rule.match(value[0])
          # First check against the multiport value, if found split and return as an array
          value_regex = Regexp.new("#{value[0]}\\s(\\S+)")
          key_value = rule.scan(value_regex)[0]
          rule_hash[key] = key_value[0].split(%r{,})
        elsif rule.match(negated_multi_regex)
          # Next check against a negated multiport value, if found split and return as an array with the first value negated
          value_regex = Regexp.new("#{negated_multi_regex}\\s(\\S+)")
          key_value = rule.scan(value_regex)[0]

          # Add '!' to the beginning of the first value to show it as negated
          split_value = key_value[0].split(%r{,})
          split_value[0] = "! #{split_value[0]}"
          rule_hash[key] = split_value
        elsif rule.match(value[1])
          # If no multi value matches, check against the regular value instead
          value_regex = Regexp.new("(?:(!)\\s)?#{value[1]}\\s(\\S+)")
          key_value = rule.scan(value_regex)[0]
          # If it is negated, combine the retrieved '!' with the actual value to make one string
          key_value[1] = [key_value[0], key_value[1]].join(' ') unless key_value[0].nil?
          rule_hash[key] = key_value[1]
        end
      when :tcp_flags
        # First find if flag is present, add a space to ensure accuracy with the more simplistic flags; i.e. `-i`
        if rule.match(Regexp.new("#{value}\\s"))
          value_regex = Regexp.new("(?:(!)\\s)?#{value}\\s(\\S+)\\s(\\S+)")
          key_value = rule.scan(value_regex)[0]
          # If a negation is found combine it with the first retrieved value, then combine both values
          key_value[1] = [key_value[0], key_value[1]].join(' ') unless key_value[0].nil?
          rule_hash[key] = [key_value[1], key_value[2]].join(' ')
        end
      when :src_type, :dst_type, :ipset, :match_mark, :mss, :connmark
        split_regex = value.split(%r{ })
        if rule.match(Regexp.new("#{split_regex[1]}\\s(?:(!)\\s)?#{split_regex[2]}\\s"))
          # The exact information retrieved changes dependeing on the key
          type_attr = [:src_type, :dst_type]
          value_regex = Regexp.new("#{split_regex[1]}\\s(?:(!)\\s)?#{split_regex[2]}\\s(\\S+)\\s?(--limit-iface-(?:in|out))?") if type_attr.include?(key)
          ip_attr = [:ipset]
          value_regex = Regexp.new("#{split_regex[1]}\\s(?:(!)\\s)?#{split_regex[2]}\\s(\\S+\\s\\S+)") if ip_attr.include?(key)
          mark_attr = [:match_mark, :mss, :connmark]
          value_regex = Regexp.new("#{split_regex[1]}\\s(?:(!)\\s)?#{split_regex[2]}\\s(\\S+)") if mark_attr.include?(key)
          # Since multiple values can be recovered, we must loop through each instance
          type_value = []
          key_value = rule.scan(value_regex)
          key_value.length.times do |i|
            type_value.append(key_value[i].join(' ').strip) if key_value[i]
          end
          # If only a single value was found return as a string
          rule_hash[key] = type_value[0] if type_value.length == 1
          rule_hash[key] = type_value if type_value.length > 1
        end
      when :state, :ctstate, :ctstatus, :month_days, :week_days
        if rule.match(Regexp.new("#{value}\\s"))
          value_regex = Regexp.new("(?:(!)\\s)?#{value}\\s(\\S+)")
          key_value = rule.scan(value_regex)
          split_value = key_value[0][1].split(%r{,})
          # If negated add to first value
          split_value[0] = [key_value[0][0], split_value[0]].join(' ') unless key_value[0][0].nil?
          # If value is meant to be Int, return as such
          int_attr = [:month_days]
          split_value = split_value.map(&:to_i) if int_attr.include?(key)
          # If only a single value is found, strip the Array wrapping
          split_value = split_value[0] if split_value.length == 1
          rule_hash[key] = split_value
        end
      when :icmp
        case protocol
        when 'IPv4', 'iptables'
          proto = 0
        when 'IPv6', 'ip6tables'
          proto = 1
        end

        if rule.match(Regexp.new("#{value[proto]}\\s"))
          value_regex = Regexp.new("#{value[proto]}\\s(\\S+)")
          key_value = rule.scan(value_regex)[0]
          rule_hash[key] = key_value[0]
        end
      when :recent
        if rule.match(Regexp.new("#{value}\\s"))
          value_regex = Regexp.new("#{value}\\s(!\\s)?--(\\S+)")
          key_value = rule.scan(value_regex)[0]
          # If it has, combine the retrieved '!' with the actual value to make one string
          key_value[1] = [key_value[0], key_value[1]].join unless key_value[0].nil?
          rule_hash[key] = key_value[1] if key_value
        end
      when :rpfilter
        if rule.match(Regexp.new("#{value}\\s--"))
          # Since the values are their own flags we can simply look for them directly
          value_regex = Regexp.new("(?:\s--(invert|validmark|loose|accept-local))")
          key_value = rule.scan(value_regex)
          return_value = []
          key_value.each do |val|
            return_value << val[0]
          end
          rule_hash[key] = return_value[0] if return_value.length == 1
          rule_hash[key] = return_value if return_value.length > 1
        end
      when :proto, :source, :destination, :iniface, :outiface, :physdev_in, :physdev_out, :src_range, :dst_range,
            :tcp_option, :uid, :gid, :mac_source, :pkttype, :ctproto, :ctorigsrc, :ctorigdst, :ctreplsrc, :ctrepldst,
            :ctorigsrcport, :ctorigdstport, :ctreplsrcport, :ctrepldstport, :ctexpire, :cgroup, :hop_limit
        # Values where negation is prior to the flag
        # First find if flag is present, add a space to ensure accuracy with the more simplistic flags; i.e. `-i`
        if rule.match(Regexp.new("#{value}\\s"))
          value_regex = Regexp.new("(?:(!)\\s)?#{value}\\s(\\S+)")
          key_value = rule.scan(value_regex)[0]
          # If it has, combine the retrieved '!' with the actual value to make one string
          key_value[1] = [key_value[0], key_value[1]].join(' ') unless key_value[0].nil?
          rule_hash[key] = key_value[1] if key_value
        end
      else # stat_mode, stat_every, stat_packet, stat_probability, socket, ipsec_dir, ipsec_policy, :ctdir,
        # :limit, :burst, :length, :rseconds, :rhitcount, :rname, :mask, :string_algo, :string_from, :string_to,
        # :jump, :goto, :clusterip_hashmode, :clusterip_clustermac, :clusterip_total_nodes, :clusterip_local_node,
        # :clusterip_hash_init, :queue_num, :nflog_group, :nflog_range, :nflog_size, :nflog_threshold,
        # :gateway, :set_mss, :set_dscp, :set_dscp_class, :todest, :tosource, :toports, :to, :log_level,
        # :reject, :set_mark, :connlimit_upto, :connlimit_above, :connlimit_mask, :time_start, :time_stop, :date_start,
        # :date_stop, :src_cc, :dst_cc, :hashlimit_upto, :hashlimit_above, :hashlimit_name, :hashlimit_burst, :hashlimit_mode,
        # :hashlimit_srcmask, :hashlimit_dstmask, :hashlimit_htable_size, :hashlimit_htable_max, :hashlimit_htable_expire,
        # :hashlimit_htable_gcinterval, :zone, :helper, :condition
        # Default return, retrieve first complete block following the key value
        # First find if flag is present, add a space to ensure accuracy with the more simplistic flags; i.e. `-j`, `--to`
        if rule.match(Regexp.new("#{value}\\s"))
          value_regex = Regexp.new("#{value}(?:\\s(!)\\s|\\s{1,2})(\\S+)")
          key_value = rule.scan(value_regex)[0]
          # If it has, combine the retrieved '!' with the actual value to make one string
          key_value[1] = [key_value[0], key_value[1]].join(' ') unless key_value[0].nil?
          # If value is meant to return as an integer/float ensure it does
          int_attr = [:stat_every, :stat_packet, :burst, :rseconds, :rhitcount, :string_from, :string_to, :clusterip_total_nodes,
                      :clusterip_local_nodes, :nflog_group, :nflog_range, :nflog_size, :nflog_threshold, :set_mss, :connlimit_upto,
                      :connlimit_above, :connlimit_mask, :hashlimit_burst, :hashlimit_srcmask, :hashlimit_dstmask, :hashlimit_htable_size,
                      :hashlimit_htable_max, :hashlimit_htable_expire, :hashlimit_htable_gcinterval, :zone]
          key_value[1] = key_value[1].to_i if int_attr.include?(key)
          if key == :stat_probability && key_value[1].include?('.')
            key_value[1] = key_value[1].to_f
          elsif key == :stat_probability
            key_value[1] = key_value[1].to_i
          end

          rule_hash[key] = key_value[1] if key_value
        end
      end
    end
    rule_hash
  end

  # Verify that the information being retrieved is correct
  # @api private
  def self.validate_get(_context, rules)
    # Verify that names are unique
    names = []
    rules.each do |rule|
      names << rule[:name]
    end
    raise ArgumentError, 'Duplicate names have been found within your Firewalls. This prevents the module from working correctly and must be manually resolved.' if names.length != names.uniq.length
    # Verify that the current order of the retrieved puppet rules is correct
  end

  # Certain attributes need custom logic to ensure that they are returning the correct information
  # @api private
  def self.process_get(_context, rule_hash, rule, counter)
    # Puppet-firewall requires that all rules have structured comments (resource names) and will fail if a
    # rule in iptables does not have a matching comment.
    if !rule_hash.key?(:name)
      num = 9000 + counter
      rule_hash[:name] = "#{num} #{Digest::SHA256.hexdigest(rule)}"
    elsif !rule_hash[:name].match(%r{(^\d+(?:[ \t-]\S+)+$)})
      num = 9000 + counter
      rule_hash[:name] = "#{num} #{rule_hash[:name]}"
    end

    # If no specific proto has been set we treat it as having `all` set
    rule_hash[:proto] = 'all' unless rule_hash[:proto]
    # Certain OS can return the proto as it;s equivalent number and we make sure to convert it in that case
    rule_hash[:proto] = PuppetX::Firewall::Utility.proto_number_to_name(rule_hash[:proto])

    # If a dscp numer is found, also return it as it's valid class name
    rule_hash[:set_dscp_class] = PuppetX::Firewall::Utility.dscp_number_to_class(rule_hash[:set_dscp]) if rule_hash[:set_dscp]

    rule_hash
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

  ###### SET ######

  # Verify that the information being set is correct
  # @api private
  def self.validate_input(_is, should)
    # Verify that name does not start with 9000-9999, this range has been reserved. Ignore check when deleting the rule
    raise ArgumentError, 'Rule name cannot start with 9000-9999, as this range is reserved for unmanaged rules.' if should[:name].match($unmanaged_rule_regex) && should[:ensure].to_s == 'present'
    # `isfragment` can only be set when `proto` is `tcp`
    raise ArgumentError, '`proto` must be set to `tcp` for `isfragment` to be true.' if should[:isfragment] && should[:proto] != 'tcp'
    # `stat_mode` must be set to `nth` for `stat_every` and `stat_packet` to be set
    raise ArgumentError, '`stat_mode` must be set to `nth` for `stat_every` to be set.' if should[:stat_every] && should[:stat_mode] != 'nth'
    raise ArgumentError, '`stat_mode` must be set to `nth` for `stat_packet` to be set.' if should[:stat_packet] && should[:stat_mode] != 'nth'
    # `stat_mode` must be set to `random` for `stat_probability` to be set
    raise ArgumentError, '`stat_mode` must be set to `random` for `stat_probability` to be set.' if should[:stat_probability] && should[:stat_mode] != 'random'

    # Verify that if dport/sport/state/ctstate/ctstatus is passed as an array, that any negation includes either the first value or al values
    [:dport, :sport, :state, :ctstate, :ctstatus].each do |key|
      next unless should[key].is_a?(Array)

      negated_values = 0
      should[key].each do |value|
        negated_values += 1 if %r{^!\s}.match?(value.to_s)
      end
      next unless (negated_values == 1 && !should[key][0].to_s.match(%r{^!\s})) ||
                  (negated_values >= 2 && negated_values != should[key].length)

      raise ArgumentError,
            "When negating a `#{key}` array, you must negate either the first given value only or all the given values."
    end
    raise ArgumentError, 'Value `any` is not valid. This behaviour should be achieved by omitting or undefining the ICMP parameter.' if should[:icmp] && should[:icmp] == 'any'
    raise ArgumentError, '`burst` cannot be set without `limit`.' if should[:burst] && !(should[:limit])

    # Verify that a correct range has been passed for `length`
    if should[:length]
      match = should[:length].to_s.match('^([0-9]+)(?::)?([0-9]+)?$')
      low = match[1].to_i
      high = match[2].to_i if match[2]
      raise ArgumentError, '`length` values must be between 0 and 65535' if (low.negative? || low > 65_535) || (!high.nil? && (high.negative? || high > 65_535 || high < low))
    end
    # Recent module
    raise ArgumentError, '`recent` must be set to `update` or `rcheck` for `rseconds` to be set.' if should[:rseconds] && (should[:recent] != 'update' && should[:recent] != 'rcheck')
    raise ArgumentError, '`rseconds` must be set for `reap` to be set.' if should[:reap] && !should[:rseconds]
    raise ArgumentError, '`recent` must be set to `update` or `rcheck` for `rhitcount` to be set.' if should[:rhitcount] && (should[:recent] != 'update' && should[:recent] != 'rcheck')
    raise ArgumentError, '`recent` must be set to `update` or `rcheck` for `rttl` to be set.' if should[:rttl] && (should[:recent] != 'update' && should[:recent] != 'rcheck')
    raise ArgumentError, '`recent` must be set for `rname` to be set.' if should[:rname] && !should[:recent]
    raise ArgumentError, '`recent` must be set for `rsource` to be set.' if should[:rsource] && !should[:recent]
    raise ArgumentError, '`recent` must be set for `rdest` to be set.' if should[:rdest] && !should[:recent]
    raise ArgumentError, '`rdest` and `rsource` are mutually exclusive, only one may be set at a time.' if should[:rsource] && should[:rdest]
    # String module
    raise ArgumentError, '`string_algo` must be set for `string` or `string_hex` to be set.' if (should[:string] || should[:string_hex]) && !(should[:string_algo])
    # NFQUEUE
    raise ArgumentError, '`queue_num`` must be between 0 and 65535' if should[:queue_num] && (should[:queue_num].to_i > 65_535 || should[:queue_num].to_i.negative?)
    # Jump
    # `2^16-1` is equal to `65_535`
    raise ArgumentError, '`nflog_group` must be between 0 and 2^16-1' if should[:nflog_group] && (should[:nflog_group].to_i > 65_535 || should[:queue_num].to_i.negative?)
    raise ArgumentError, 'When setting `jump => TEE`, the gateway property is required' if should[:jump] == 'TEE' && !should[:gateway]
    raise ArgumentError, 'When setting `jump => TCPMSS`, the `set_mss` or `clamp_mss_to_pmtu` property is required' if should[:jump] == 'TCPMSS' && !(should[:set_mss] || should[:clamp_mss_to_pmtu])
    raise ArgumentError, 'When setting `jump => DSCP`, the `set_dscp` or `set_dscp_class` property is required' if should[:jump] == 'DSCP' && !(should[:set_dscp] || should[:set_dscp_class])
    raise ArgumentError, 'Parameter `jump => DNAT` only applies to `table => nat`' if should[:jump] == 'DNAT' && should[:table] != 'nat'
    raise ArgumentError, 'Parameter `jump => DNAT` must have `todest` parameter' if (should[:jump] == 'DNAT' && !should[:todest]) || (should[:jump] != 'DNAT' && should[:todest])
    raise ArgumentError, 'Parameter `jump => SNAT` only applies to `table => nat`' if should[:jump] == 'SNAT' && should[:table] != 'nat'
    raise ArgumentError, 'Parameter `jump => SNAT` must have `tosource` parameter' if (should[:jump] == 'SNAT' && !should[:tosource]) || (should[:jump] != 'SNAT' && should[:tosource])
    raise ArgumentError, 'Parameter `checksum_fill` requires `jump => CHECKSUM` and `table => mangle`' if should[:checksum_fill] && !(should[:jump] == 'CHECKSUM' && should[:table] == 'mangle')

    [:log_prefix, :log_level, :log_uid, :log_tcp_sequence, :log_tcp_options, :log_ip_options].each do |log|
      raise ArgumentError, "Parameter `#{log}` requires `jump => LOG`" if should[log] && should[:jump] != 'LOG'
    end
    raise ArgumentError, 'Parameter `jump => CT` only applies to `table => raw`' if should[:jump] == 'CT' && should[:table] != 'raw'
    raise ArgumentError, 'Parameter `zone` requires `jump => CT`' if should[:zone] && should[:jump] != 'CT'
    raise ArgumentError, 'Parameter `helper` requires `jump => CT`'  if should[:helper] && should[:jump] != 'CT'
    raise ArgumentError, 'Parameter `notrack` requires `jump => CT`' if should[:notrack] && should[:jump] != 'CT'
    # Connlimit
    raise ArgumentError, 'Parameter `connlimit_mask` requires either `connlimit_upto` or `connlimit_above`' if should[:connlimit_mask] && !(should[:connlimit_upto] || should[:connlimit_above])

    # Hashlimit
    [:hashlimit_upto, :hashlimit_above, :hashlimit_name, :hashlimit_burst, :hashlimit_mode, :hashlimit_srcmask, :hashlimit_dstmask,
     :hashlimit_htable_size, :hashlimit_htable_max, :hashlimit_htable_expire, :hashlimit_htable_gcinterval].each do |hash|
      next unless should[hash] && (!should[:hashlimit_name] || !(should[:hashlimit_upto] || should[:hashlimit_above]))

      raise ArgumentError, 'Parameter `hashlimit_name` and either `hashlimit_upto` or `hashlimit_above` are required when setting any `hashlimit` attribute.'
    end
    raise ArgumentError, '`hashlimit_upto` and `hashlimit_above` are mutually exclusive, only one may be set at a time.' if should[:hashlimit_upto] && should[:hashlimit_above]

    # Protocol
    ipv4_only = [:clusterip_new, :clusterip_hashmode, :clusterip_clustermac, :clusterip_total_nodes, :clusterip_local_node, :clusterip_hash_init]
    ipv4_only.each do |ipv4|
      raise ArgumentError, "Parameter `#{ipv4}` is specific to the `IPv4` protocol" if should[ipv4] && !(should[:protocol] == 'IPv4' || should[:protocol] == 'iptables')
    end
    ipv6_only = [:hop_limit, :ishasmorefrags, :islastfrag, :isfirstfrag]
    ipv6_only.each do |ipv6|
      raise ArgumentError, "Parameter `#{ipv6}` is specific to the `IPv6` protocol" if should[ipv6] && !(should[:protocol] == 'IPv6' || should[:protocol] == 'ip6tables')
    end
    ## Array elements must be unique
    [:dst_type, :src_type].each do |key|
      next unless should[key].is_a?(Array)
      raise ArgumentError, "`#{key}` elements must be unique" if should[key].map { |type| type.to_s.gsub(%r{--limit-iface-(in|out)}, '') }.uniq.length != should[key].length
    end
    # Log prefix size is limited
    raise ArgumentError, 'Parameter `nflog_prefix`` must be less than 64 characters' if should[:nflog_prefix] && should[:nflog_prefix].length > 64

    [:dst_range, :src_range].each do |key|
      next unless should[key]

      matches = %r{^([^\-/]+)-([^\-/]+)$}.match(should[key])
      raise(ArgumentError, 'The IP range must be in `IP1-IP2` format.') unless matches

      [matches[1], matches[2]].each do |addr|
        begin # rubocop:disable Style/RedundantBegin
          PuppetX::Firewall::Utility.host_to_ip(addr, should[:protocol])
        rescue StandardError
          raise(ArgumentError, "Invalid IP address `#{addr}` in range `#{should[key]}`")
        end
      end
    end
  end

  # Certain attributes need processed in ways that can vary between IPv4 and IPv6
  # @api private
  def self.process_input(should)
    # `dport`, `sport` `state` `ctstate` and `ctstatus` arrays should only have the first value negated.
    [:dport, :sport, :state, :ctstate, :ctstatus].each do |key|
      next unless should[key].is_a?(Array)

      negated = true if %r{^!\s}.match?(should[key][0].to_s)
      should[key].each_with_index do |_value, _index|
        should[key] = should[key].map { |value| value.to_s.tr('! ', '') }
      end
      should[key][0] = ['!', should[key][0]].join(' ') if negated
    end

    # `jump` common values should always be uppercase
    jump_common_values = ['accept', 'reject', 'drop', 'queue', 'return', 'dnat', 'snat', 'log', 'nflog',
                          'netmp', 'masquerade', 'redirect', 'mark', 'ct']
    should[:jump] = should[:jump].upcase if should[:jump] && jump_common_values.include?(should[:jump].downcase)

    # `source` and `destination` must be put through host_to_mask
    should[:source] = PuppetX::Firewall::Utility.host_to_mask(should[:source], should[:protocol]) if should[:source]
    should[:destination] = PuppetX::Firewall::Utility.host_to_mask(should[:destination], should[:protocol]) if should[:destination]

    # ct attributes must be put through host_to_mask with certain masks then being removed
    ct = [:ctorigsrc, :ctorigdst, :ctreplsrc, :ctrepldst]
    ct.each do |c|
      break unless should[c]

      value = PuppetX::Firewall::Utility.host_to_mask(should[c], should[:protocol])
      should[c] = if should[:protocol] == 'IPv4'
                    value.chomp('/32')
                  else
                    value.chomp('/128')
                  end
    end

    # `icmp` needs to be converted to a number if passed as a string
    should[:icmp] = PuppetX::Firewall::Utility.icmp_name_to_number(should[:icmp], should[:protocol]) if should[:icmp]

    # `log_level` needs to be converted to a number if passed as a string
    should[:log_level] = PuppetX::Firewall::Utility.log_level_name_to_number(should[:log_level]) if should[:log_level]

    # `set_mark`, `match_mark` and `connmark` must be applied in hexidecimal format
    should[:set_mark] = PuppetX::Firewall::Utility.mark_mask_to_hex(should[:set_mark]) if should[:set_mark]
    should[:match_mark] = PuppetX::Firewall::Utility.mark_to_hex(should[:match_mark]) if should[:match_mark]
    should[:connmark] = PuppetX::Firewall::Utility.mark_to_hex(should[:connmark]) if should[:connmark]

    # `time_start` and `time_stop` must be applied in full HH:MM:SS format
    time = [:time_start, :time_stop]
    time.each do |t|
      should[t] = "0#{should[t]}" if %r{^([0-9]):}.match?(should[t])
      should[t] = "#{should[t]}:00" if %r{^([0-9]|0[0-9]|1[0-9]|2[0-3]):[0-5][0-9]$}.match?(should[t])
    end

    # If `sport/dport` range has been passed with `-`, replace with `:`
    should[:sport] = should[:sport].to_s.tr('-', ':') if should[:sport].is_a?(String)
    should[:dport] = should[:dport].to_s.tr('-', ':') if should[:dport].is_a?(String)
    should[:sport] = should[:sport].map { |port| port.to_s.tr('-', ':') } if should[:sport].is_a?(Array)
    should[:dport] = should[:dport].map { |port| port.to_s.tr('-', ':') } if should[:dport].is_a?(Array)

    should
  end

  # Converts a given hash value to a command line argument
  # @api private
  def self.hash_to_rule(_context, _name, rule)
    arguments = ''

    # We loop through an ordered list of all flags as the order that they are added is important
    $resource_list.each do |key|
      next unless rule[key]

      value = rule[key]

      # Ensure that the necesary module (`-m`) arguments are added when needed
      # addrtype and ipset are exceptions as they need to preface each instance
      @module_to_argument_mapping.each do |modules|
        # Skip unless the key is part of the module
        next unless modules[1].include?(key)
        # Skip if the module flag has already been added
        next if arguments.match(Regexp.new("-m #{modules[0]}"))

        # Add the module flag
        arguments += " -m #{modules[0]}"
      end

      # if resource is known_boolean
      if $known_booleans.include?(key)
        # If value is true, append command to arguments
        arguments += " #{$resource_map[key]}" if value
        next
      end

      # check for existence, retrieve string that follows if it is
      # certain resources may need special rules
      case key
      when :name, :string, :string_hex, :bytecode, :u32, :nflog_prefix, :log_prefix
        arguments += " #{[$resource_map[key], "'#{rule[key]}'"].join(' ')}" if rule[key].match?(%r{^[^!]}) # if standard
        arguments += " #{['!', $resource_map[key], "'#{rule[key].gsub(%r{^!\s?}, '')}'"].join(' ')}" if rule[key].match?(%r{^!}) # if negated
      when :sport, :dport
        if rule[key].is_a?(Array) && rule[key][0].to_s.match(%r{^!})
          # Negated Multiport
          split_comannd = $resource_map[key][0].split(%r{ })
          negated_command = [split_comannd[0], split_comannd[1], '!', split_comannd[2]].join(' ')
          value = rule[key].join(',').gsub(%r{^!\s?}, '')
          arguments += " #{[negated_command, value].join(' ')}"
        elsif rule[key].is_a?(Array)
          # Standard Multiport
          arguments += " #{[$resource_map[key][0], rule[key].join(',')].join(' ')}"
        elsif rule[key].to_s.match?(%r{^!})
          # Negated Standard
          arguments += " #{['!', $resource_map[key][1], rule[key].gsub(%r{^!\s?}, '')].join(' ')}"
        else
          # Standard
          arguments += " #{[$resource_map[key][1], rule[key]].join(' ')}"
        end
      when :src_type, :dst_type, :ipset, :match_mark, :mss, :connmark
        # Code for if value requires it's own flag each time it is applied
        split_command = $resource_map[key].split(%r{ })
        negated_command = [split_command[0], split_command[1], '!', split_command[2]].join(' ')

        # If a string, wrap as an array to simplify the code
        rule[key] = [rule[key]] if rule[key].is_a?(String)
        rule[key].each do |ru|
          arguments += " #{$resource_map[key]} #{ru}" unless ru.match?(%r{^!})
          arguments += " #{negated_command} #{ru.gsub(%r{^!\s?}, '')}" if ru.match?(%r{^!})
        end
      when :state, :ctstate, :ctstatus, :month_days, :week_days
        # Code for if value is an array and all values are joined together and passed as part of a single flag
        # If not an array, wrap as an array to simplify the code
        rule[key] = [rule[key]] unless rule[key].is_a?(Array)
        int_attr = [:month_days]
        arguments += " #{[$resource_map[key], rule[key].join(',')].join(' ')}" if int_attr.include?(key) || rule[key][0].match(%r{^[^!]}) # if standard
        arguments += " #{['!', $resource_map[key], rule[key].join(',').gsub(%r{^!\s?}, '')].join(' ')}" if !int_attr.include?(key) && rule[key][0].match(%r{^!}) # if negated
      when :icmp
        case rule[:protocol]
        when 'IPv4', 'iptables'
          proto = 0
        when 'IPv6', 'ip6tables'
          proto = 1
        end
        # Retrieve the correct command for the protocol
        # A command is generated to be used for negation
        split_comannd = $resource_map[key][proto].split(%r{ })
        negated_command = [split_comannd[0], split_comannd[1], '!', split_comannd[2]].join(' ')

        arguments += " #{[$resource_map[key][proto], rule[key]].join(' ')}" if rule[key].match?(%r{^[^!]}) # if standard
        arguments += " #{[negated_command, rule[key].gsub(%r{^!\s?}, '')].join(' ')}" if rule[key].match?(%r{^!}) # if negated
      when :recent
        # Add value after command, if negated add negation before command
        # Preface the value of recent with `--`
        arguments += " #{$resource_map[key]} --#{rule[key]}" if rule[key].match?(%r{^[^!]}) # if standard
        arguments += " #{$resource_map[key]} ! --#{rule[key].gsub(%r{^!\s?}, '')}" if rule[key].match?(%r{^!}) # if negated
      when :rpfilter
        # Add value after command
        # Preface the value of recent with `--`
        # If a string, wrap as an array to simplify the code
        rule[key] = [rule[key]] if rule[key].is_a?(String)
        arguments += " #{$resource_map[key]} --#{rule[key].join(' --')}"
      when :proto, :source, :destination, :iniface, :outiface, :physdev_in, :physdev_out, :src_range, :dst_range,
            :tcp_option, :tcp_flags, :uid, :gid, :mac_source, :pkttype, :ctproto, :ctorigsrc, :ctorigdst, :ctreplsrc,
            :ctrepldst, :ctorigsrcport, :ctorigdstport, :ctreplsrcport, :ctrepldstport, :ctexpire, :cgroup, :hop_limit
        # Add value after command, if negated add negation before command
        arguments += " #{[$resource_map[key], rule[key]].join(' ')}" if rule[key].is_a?(Integer) || rule[key].match?(%r{^[^!]}) # if standard
        arguments += " #{['!', $resource_map[key], rule[key].gsub(%r{^!\s?}, '')].join(' ')}" if rule[key].is_a?(String) && rule[key].match?(%r{^!}) # if negated
      else # :chain, stat_mode, stat_every, stat_packet, stat_probability, socket, ipsec_dir, ipsec_policy, :ctdir,
        # :limit, :burst, :length, :rseconds, :rhitcount, :rname, :mask, :string_algo, :string_from, :string_to,
        # :jump, :goto, :clusterip_hashmode, :clusterip_clustermac, :clusterip_total_nodes, :clusterip_local_node,
        # :clusterip_hash_init, :queue_num, :nflog_group, :nflog_range, :nflog_size, :nflog_threshold,
        # :gateway, :set_mss, :set_dscp, :set_dscp_class, :todest, :tosource, :toports, :to, :log_level,
        # :reject, :set_mark, :connlimit_upto, :connlimit_above, :connlimit_mask, :time_start, :time_stop, :date_start,
        # :date_stop, :src_cc, :dst_cc, :hashlimit_upto, :hashlimit_above, :hashlimit_name, :hashlimit_burst, :hashlimit_mode,
        # :hashlimit_srcmask, :hashlimit_dstmask, :hashlimit_htable_size, :hashlimit_htable_max, :hashlimit_htable_expire,
        # :hashlimit_htable_gcinterval, :zone, :helper, :condition
        # Add value after command
        arguments += " #{[$resource_map[key], rule[key]].join(' ')}"
      end
    end
    arguments
  end

  # Find the correct position for our new rule in its chain
  # This has been lifted from the previous provider in order to maintain the logic between them
  # @api private
  def self.insert_order(context, name, chain, table, protocol)
    rules = []
    # Find any rules that match the given chain and table pairing
    Puppet::Provider::Firewall::Firewall.get_rules(context, true, [protocol]).each do |rule|
      rules << rule[:name] if rule[:chain] == chain && rule[:table] == table
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
    unnamed_offset -= 1 if offset_rule.match($unmanaged_rule_regex) && !name.match(%r{^9})

    # Insert our new or updated rule in the correct order of named rules, but
    # offset for unnamed rules.
    sorted_rules = rules.reject { |r| r.match($unmanaged_rule_regex) }.sort
    sorted_rules.index(name) + 1 + unnamed_offset
  end
end
