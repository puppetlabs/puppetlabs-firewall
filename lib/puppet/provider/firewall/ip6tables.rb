Puppet::Type.type(:firewall).provide :ip6tables, :parent => :iptables, :source => :ip6tables do
  @doc = "Ip6tables type provider"

  has_feature :iptables
  has_feature :connection_limiting
  has_feature :hop_limiting
  has_feature :rate_limiting
  has_feature :recent_limiting
  has_feature :snat
  has_feature :dnat
  has_feature :interface_match
  has_feature :icmp_match
  has_feature :owner
  has_feature :state_match
  has_feature :reject_type
  has_feature :log_level
  has_feature :log_prefix
  has_feature :mark
  has_feature :tcp_flags
  has_feature :pkttype
  has_feature :ishasmorefrags
  has_feature :islastfrag
  has_feature :isfirstfrag
  has_feature :socket
  has_feature :address_type
  has_feature :iprange
  has_feature :ipsec_dir
  has_feature :ipsec_policy
  has_feature :mask
  has_feature :ipset

  optional_commands({
    :ip6tables      => 'ip6tables',
    :ip6tables_save => 'ip6tables-save',
  })

  confine :kernel => :linux

  ip6tables_version = Facter.fact('ip6tables_version').value
  if (ip6tables_version and Puppet::Util::Package.versioncmp(ip6tables_version, '1.4.1') < 0)
    mark_flag = '--set-mark'
  else
    mark_flag = '--set-xmark'
  end


  def initialize(*args)
    ip6tables_version = Facter.value('ip6tables_version')
    if ip6tables_version and ip6tables_version.match /1\.3\.\d/
      raise ArgumentError, 'The ip6tables provider is not supported on version 1.3 of iptables'
    else
      super
    end
  end

  def self.iptables(*args)
    ip6tables(*args)
  end

  def self.iptables_save(*args)
    ip6tables_save(*args)
  end

  @protocol = "IPv6"

  @resource_map = {
    :burst            => "--limit-burst",
    :connlimit_above  => "-m connlimit --connlimit-above",
    :connlimit_mask   => "--connlimit-mask",
    :connmark         => "-m connmark --mark",
    :ctstate          => "-m conntrack --ctstate",
    :destination      => "-d",
    :dport            => ["-m multiport --dports", "--dport"],
    :dst_range        => '-m iprange --dst-range',
    :dst_type         => "-m addrtype --dst-type",
    :gid              => "-m owner --gid-owner",
    :hop_limit        => "-m hl --hl-eq",
    :icmp             => "-m icmp6 --icmpv6-type",
    :iniface          => "-i",
    :ipsec_dir        => "-m policy --dir",
    :ipsec_policy     => "--pol",
    :ipset            => "-m set --match-set",
    :isfirstfrag      => "-m frag --fragid 0 --fragfirst",
    :ishasmorefrags   => "-m frag --fragid 0 --fragmore",
    :islastfrag       => "-m frag --fragid 0 --fraglast",
    :jump             => "-j",
    :limit            => "-m limit --limit",
    :log_level        => "--log-level",
    :log_prefix       => "--log-prefix",
    :mask             => "--mask",
    :name             => "-m comment --comment",
    :mac_source       => ["-m mac --mac-source", "--mac-source"],
    :outiface         => "-o",
    :pkttype          => "-m pkttype --pkt-type",
    :port             => '-m multiport --ports',
    :proto            => "-p",
    :rdest            => "--rdest",
    :reap             => "--reap",
    :recent           => "-m recent",
    :reject           => "--reject-with",
    :rhitcount        => "--hitcount",
    :rname            => "--name",
    :rseconds         => "--seconds",
    :rsource          => "--rsource",
    :rttl             => "--rttl",
    :set_mark         => mark_flag,
    :socket           => "-m socket",
    :source           => "-s",
    :sport            => ["-m multiport --sports", "--sport"],
    :src_range        => '-m iprange --src-range',
    :src_type         => "-m addrtype --src-type",
    :stat_every       => '--every',
    :stat_mode        => "-m statistic --mode",
    :stat_packet      => '--packet',
    :stat_probability => '--probability',
    :state            => "-m state --state",
    :table            => "-t",
    :tcp_flags        => "-m tcp --tcp-flags",
    :todest           => "--to-destination",
    :toports          => "--to-ports",
    :tosource         => "--to-source",
    :uid              => "-m owner --uid-owner",
    :physdev_in       => "-m physdev --physdev-in",
    :physdev_out      => "-m physdev --physdev-out",
  }

  # These are known booleans that do not take a value, but we want to munge
  # to true if they exist.
  @known_booleans = [
    :ishasmorefrags,
    :islastfrag,
    :isfirstfrag,
    :rsource,
    :rdest,
    :reap,
    :rttl,
    :socket
  ]

  # Create property methods dynamically
  (@resource_map.keys << :chain << :table << :action).each do |property|
    if @known_booleans.include?(property) then
      # The boolean properties default to '' which should be read as false
      define_method "#{property}" do
        @property_hash[property] = :false if @property_hash[property] == nil
        @property_hash[property.to_sym]
      end
    else
      define_method "#{property}" do
        @property_hash[property.to_sym]
      end
    end

    if property == :chain
      define_method "#{property}=" do |value|
        if @property_hash[:chain] != value
          raise ArgumentError, "Modifying the chain for existing rules is not supported."
        end
      end
    else
      define_method "#{property}=" do |value|
        @property_hash[:needs_change] = true
      end
    end
  end

  # This is the order of resources as they appear in iptables-save output,
  # we need it to properly parse and apply rules, if the order of resource
  # changes between puppet runs, the changed rules will be re-applied again.
  # This order can be determined by going through iptables source code or just tweaking and trying manually
  # (Note: on my CentOS 6.4 ip6tables-save returns -m frag on the place
  # I put it when calling the command. So compability with manual changes
  # not provided with current parser [georg.koester])
  @resource_list = [:table, :source, :destination, :iniface, :outiface, :physdev_in,
    :physdev_out, :proto, :ishasmorefrags, :islastfrag, :isfirstfrag, :src_range, :dst_range,
    :tcp_flags, :gid, :uid, :mac_source, :sport, :dport, :port, :dst_type,
    :src_type, :socket, :pkttype, :name, :ipsec_dir, :ipsec_policy, :state,
    :ctstate, :icmp, :hop_limit, :limit, :burst, :recent, :rseconds, :reap,
    :rhitcount, :rttl, :rname, :mask, :rsource, :rdest, :ipset, :jump, :todest,
    :tosource, :toports, :log_level, :log_prefix, :reject, :set_mark,
    :connlimit_above, :connlimit_mask, :connmark]

end
