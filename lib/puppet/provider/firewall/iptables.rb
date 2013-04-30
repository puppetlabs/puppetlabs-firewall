require 'puppet/provider/firewall'
require 'digest/md5'

Puppet::Type.type(:firewall).provide :iptables, :parent => Puppet::Provider::Firewall do
  include Puppet::Util::Firewall

  @doc = "Iptables type provider"

  has_feature :iptables
  has_feature :rate_limiting
  has_feature :snat
  has_feature :dnat
  has_feature :interface_match
  has_feature :icmp_match
  has_feature :owner
  has_feature :state_match
# This is like state_match but using the nf_conntrack module
  has_feature :ctstate_match
  has_feature :reject_type
  has_feature :log_level
  has_feature :log_prefix
  has_feature :mark
  has_feature :tcp_flags
  has_feature :pkttype
  has_feature :addrtype

  commands :iptables => '/sbin/iptables'
  commands :iptables_save => '/sbin/iptables-save'

  defaultfor :kernel => :linux

  iptables_version = Facter.fact('iptables_version').value
  if (iptables_version and Puppet::Util::Package.versioncmp(iptables_version, '1.4.1') < 0)
    mark_flag = '--set-mark'
  else
    mark_flag = '--set-xmark'
  end

  @resource_map = {
    :burst => "--limit-burst",
    :destination => "-d",
    :dport => "-m multiport --dports",
    :dport_udp => "-m udp --dport",
    :dport_tcp => "-m tcp --dport",
    :gid => "-m owner --gid-owner",
    :icmp => "-m icmp --icmp-type",
    :iniface => "-i",
    :jump => "-j",
    :limit => "-m limit --limit",
    :log_level => "--log-level",
    :log_prefix => "--log-prefix",
    :name => "-m comment --comment",
    :outiface => "-o",
    :port => '-m multiport --ports',
    :proto => "-p",
    :reject => "--reject-with",
    :set_mark => mark_flag,
    :source => "-s",
    :sport => "-m multiport --sports",
    :sport_udp => "-m udp --sport",
    :sport_tcp => "-m tcp --sport",
    :state => "-m state --state",
    :ctstate => "-m conntrack --ctstate",
    :table => "-t",
    :tcp_flags => "-m tcp --tcp-flags",
    :todest => "--to-destination",
    :toports => "--to-ports",
    :tosource => "--to-source",
    :uid => "-m owner --uid-owner",
    :pkttype => "-m pkttype --pkt-type",
    :addrtype => "-m addrtype --src-type"
  }

  # Create property methods dynamically
  (@resource_map.keys << :chain << :table << :action).each do |property|
    define_method "#{property}" do
      @property_hash[property.to_sym]
    end

    define_method "#{property}=" do
      @property_hash[:needs_change] = true
    end
  end

  # This is the order of resources as they appear in iptables-save output,
  # we need it to properly parse and apply rules, if the order of resource
  # changes between puppet runs, the changed rules will be re-applied again.
  # This order can be determined by going through iptables source code or just tweaking and trying manually
  @resource_list = [:table, :source, :destination, :iniface, :outiface,
    :proto, :tcp_flags, :gid, :uid, :sport, :dport, :sport_udp, :sport_tcp, :dport_udp, :dport_tcp, :port, :pkttype, :addrtype, :name, :state, :ctstate, :icmp, :limit, :burst,
    :jump, :todest, :tosource, :toports, :log_prefix, :log_level, :reject, :set_mark]

  def insert
    debug 'Inserting rule %s' % resource[:name]
    iptables insert_args
  end

  def update
    debug 'Updating rule %s' % resource[:name]
    iptables update_args
  end

  def delete
    debug 'Deleting rule %s' % resource[:name]
    iptables delete_args
  end

  def exists?
    properties[:ensure] != :absent
  end

  # Flush the property hash once done.
  def flush
    debug("[flush]")
    if @property_hash.delete(:needs_change)
      notice("Properties changed - updating rule")
      update
    end
    @property_hash.clear
  end

  def self.instances
    debug "[instances]"
    table = nil
    rules = []
    counter = 1

    # String#lines would be nice, but we need to support Ruby 1.8.5
    iptables_save.split("\n").each do |line|
      unless line =~ /^\#\s+|^\:\S+|^COMMIT|^FATAL/
        if line =~ /^\*/
          table = line.sub(/\*/, "")
        else
          if hash = rule_to_hash(line, table, counter)
            rules << new(hash)
            counter += 1
          end
        end
      end
    end
    rules
  end

  def self.rule_to_hash(line, table, counter)
    hash = {}
    keys = []
    values = line.dup

    # --tcp-flags takes two values; we cheat by adding " around it
    # so it behaves like --comment
    values = values.sub(/--tcp-flags (\S*) (\S*)/, '--tcp-flags "\1 \2"')

    @resource_list.reverse.each do |k|
      if values.slice!(/\s#{@resource_map[k]}/)
        keys << k
      end
    end

    # Manually remove chain
    values.slice!('-A')
    keys << :chain

    keys.zip(values.scan(/"[^"]*"|\S+/).reverse) { |f, v| hash[f] = v.gsub(/"/, '') }

    # Normalise all rules to CIDR notation.
    [:source, :destination].each do |prop|
      begin
        hash[prop] = Puppet::Util::IPCidr.new(hash[prop]).cidr unless hash[prop].nil?
      rescue
      end
    end

    [:dport, :dport_udp, :dport_tcp, :sport, :sport_udp, :sport_tcp, :port, :state, :ctstate].each do |prop|
      hash[prop] = hash[prop].split(',') if ! hash[prop].nil?
    end

    # Our type prefers hyphens over colons for ranges so ...
    # Iterate across all ports replacing colons with hyphens so that ranges match
    # the types expectations.
    [:dport, :dport_udp, :dport_cp, :sport, :sport_udp, :sport_tcp, :port].each do |prop|
      next unless hash[prop]
      hash[prop] = hash[prop].collect do |elem|
        elem.gsub(/:/,'-')
      end
    end

    # States should always be sorted. This ensures that the output from
    # iptables-save and user supplied resources is consistent.
    hash[:state] = hash[:state].sort unless hash[:state].nil?
    hash[:ctstate] = hash[:ctstate].sort unless hash[:ctstate].nil?

    # This forces all existing, commentless rules to be moved to the bottom of the stack.
    # Puppet-firewall requires that all rules have comments (resource names) and will fail if
    # a rule in iptables does not have a comment. We get around this by appending a high level
    # This also works for rules with actual comments
    if ! hash[:name] or ! hash[:name].match(/^[\d]*\ /)
      hash[:name] = "9999 #{Digest::MD5.hexdigest(line)}"
    end

    # Iptables defaults to log_level '4', so it is omitted from the output of iptables-save.
    # If the :jump value is LOG and you don't have a log-level set, we assume it to be '4'.
    if hash[:jump] == 'LOG' && ! hash[:log_level]
      hash[:log_level] = '4'
    end

    hash[:line] = line
    hash[:provider] = self.name.to_s
    hash[:table] = table
    hash[:ensure] = :present

    # Munge some vars here ...

    # Proto should equal 'all' if undefined
    hash[:proto] = "all" if !hash.include?(:proto)

    # If the jump parameter is set to one of: ACCEPT, REJECT or DROP then
    # we should set the action parameter instead.
    if ['ACCEPT','REJECT','DROP'].include?(hash[:jump]) then
      hash[:action] = hash[:jump].downcase
      hash.delete(:jump)
    end

    hash
  end

  def insert_args
    args = []
    args << ["-I", resource[:chain], insert_order]
    args << general_args
    args
  end

  def update_args
    args = []
    args << ["-R", resource[:chain], insert_order]
    args << general_args
    args
  end

  def delete_args
    count = []
    line = properties[:line].gsub(/\-A/, '-D')
    line = line.split
    # Get a copy of the line array to iterate over to find comments
    tmp_line = line
    counter = 0
    # Somewhat simple state machine to track the start and end of
    # comment sections that are found
    found_comment_start = false
    found_comment_end = false
    set_comment_start = false
    set_comment_end = false
        
    # Here we want to iterate over each segement of the array
    # if we find the start of the comment as denoted by --comment
    # take the next item in the array and prepend a " to it
    # Once we know we've found the start of a comment, find the next
    # command operator which will start with a - and append a " to the
    # preceeding segment of the array
    #
    # This will probably barf if there is a comment that includes a -X in it
    #
    # It might make sense to iterate over the @resource_map here
    #
    # I'm not positive if the comment allows a - in it either
    #
    # Going to test/confirm that this fixes the issue, then look into iterating over
    # the @resource_map if - is allowed in the comment
    tmp_line.each do |line_segment|
      if found_comment_start and line_segment=~ /^"/
          found_comment_start = false
      end
      if found_comment_start and not set_comment_start and not line_segment=~ /^"/
          # We've found the start of the comment
          # Prepend " to the element in the original array
          # Set a marker that we've found the start comment
          # We want this code to come int the loop before the 
          # comment detection as to not have to track additional state
          line[counter] = '"' + line[counter]
          set_comment_start = true
      end
      if line_segment == '--comment'
          # Confirm that we're starting a comment and set flag
          found_comment_start = true
          found_comment_index = counter
      end
      if found_comment_start and not found_comment_end and set_comment_start and line_segment=~/^-/
          # Confirm that we've set the start flag
          # We've confirmed that we're at the end of the comment
          line[counter - 1] = line[counter - 1] + '"'
          found_comment_end = true
      end
      counter += 1
    end


    line.unshift("-t", properties[:table])
  
    # Return array without nils
    line.compact
  end

  def general_args
    debug "Current resource: %s" % resource.class

    args = []
    resource_list = self.class.instance_variable_get('@resource_list')
    resource_map = self.class.instance_variable_get('@resource_map')

    resource_list.each do |res|
      resource_value = nil
      if (resource[res]) then
        resource_value = resource[res]
      elsif res == :jump and resource[:action] then
        # In this case, we are substituting jump for action
        resource_value = resource[:action].to_s.upcase
      else
        next
      end

      args << resource_map[res].split(' ')

      # For sport, sport_{udp,tcp} and dport, dport_{udp,tcp}, convert hyphens to colons since the type
      # expects hyphens for ranges of ports.
      if [:sport, :sport_udp, :sport_tcp, :dport, :dport_udp, :dport_tcp, :port].include?(res) then
        resource_value = resource_value.collect do |elem|
          elem.gsub(/-/, ':')
        end
      end

      # our tcp_flags takes a single string with comma lists separated
      # by space
      # --tcp-flags expects two arguments
      if res == :tcp_flags
        one, two = resource_value.split(' ')
        args << one
        args << two
      elsif resource_value.is_a?(Array)
        args << resource_value.join(',')
      else
        args << resource_value
      end
    end

    args
  end

  def insert_order
    debug("[insert_order]")
    rules = []

    # Find list of current rules based on chain and table
    # Sometimes rules don't have a table
    # Comparing will never match if there is no table
    self.class.instances.each do |rule|
      if rule.table
        if rule.chain == resource[:chain].to_s and rule.table == resource[:table].to_s
            rules << rule.name
        end
      elsif !rule.table
        if rule.chain == resource[:chain].to_s
            rules << rule.name
        end
      end
    end

    # No rules at all? Just bail now.
    return 1 if rules.empty?

    my_rule = resource[:name].to_s
    rules << my_rule
    rules.sort.index(my_rule) + 1
  end
end
