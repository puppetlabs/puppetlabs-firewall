# frozen_string_literal: true

require 'puppet_x'
require 'socket'
require 'resolv'
require_relative 'ipcidr'

module PuppetX::Firewall # rubocop:disable Style/ClassAndModuleChildren
  # A utility class meant to contain re-usable code
  class Utility
    # Save any current iptables changes so they are retained upon restart
    def self.persist_iptables(context, name, protocol)
      os_key = Facter.value('os')['family']
      cmd = case os_key
            when 'RedHat'
              case protocol
              when 'IPv4', 'iptables'
                ['/usr/libexec/iptables/iptables.init', 'save']
              when 'IPv6', 'ip6tables'
                ['/usr/libexec/iptables/ip6tables.init', 'save']
              end
            when 'Debian'
              fact = Facter.fact(:iptables_persistent_version)
              fact.flush if fact.respond_to?(:flush)
              persist_ver = fact.value

              case protocol
              when 'IPv4', 'IPv6', 'iptables', 'ip6tables'
                if persist_ver && Puppet::Util::Package.versioncmp(persist_ver, '1.0').positive?
                  ['/usr/sbin/service', 'netfilter-persistent', 'save']
                else
                  ['/usr/sbin/service', 'iptables-persistent', 'save']
                end
              end
            when 'Archlinux'
              case protocol
              when 'IPv4', 'iptables'
                ['/bin/sh', '-c', '/usr/sbin/iptables-save > /etc/iptables/iptables.rules']
              when 'IPv6', 'ip6tables'
                ['/bin/sh', '-c', '/usr/sbin/ip6tables-save > /etc/iptables/ip6tables.rules']
              end
            when 'Suse'
              case protocol
              when 'IPv4', 'iptables'
                ['/bin/sh', '-c', '/usr/sbin/iptables-save > /etc/sysconfig/iptables']
              end
            else
              # Catch unsupported OSs
              debug('firewall: Rule persistence is not supported for this type/OS')
              return
            end

      # Run the persist command within a rescue block
      begin
        context.notice("Ensuring changes to '#{name}' persist")
        Puppet::Provider.execute(cmd)
      rescue Puppet::ExecutionFailure => e
        warn "Unable to persist firewall rules: #{e}"
      end
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

    # Takes an address and protocol and returns the address in CIDR notation.
    #
    # The protocol is only used when the address is a hostname.
    #
    # If the address is:
    #
    #   - A hostname:
    #     It will be resolved
    #   - An IPv4 address:
    #     It will be qualified with a /32 CIDR notation
    #   - An IPv6 address:
    #     It will be qualified with a /128 CIDR notation
    #   - An IP address with a CIDR notation:
    #     It will be normalised
    #   - An IP address with a dotted-quad netmask:
    #     It will be converted to CIDR notation
    #   - Any address with a resulting prefix length of zero:
    #     It will return nil which is equivilent to not specifying an address
    #
    def self.host_to_ip(value, proto = nil)
      begin
        value = PuppetX::Firewall::IPCidr.new(value)
      rescue StandardError
        family = case proto
                 when 'IPv4', 'iptables'
                   Socket::AF_INET
                 when 'IPv6', 'ip6tables'
                   Socket::AF_INET6
                 when nil
                   raise ArgumentError, 'Proto must be specified for a hostname'
                 else
                   raise ArgumentError, "Unsupported address family: #{proto}"
                 end

        new_value = nil
        Resolv.each_address(value) do |addr|
          begin # rubocop:disable Style/RedundantBegin
            new_value = PuppetX::Firewall::IPCidr.new(addr, family)
            break
          rescue StandardError # looking for the one that works # rubocop:disable Lint/SuppressedException
          end
        end

        raise "Failed to resolve hostname #{value}" if new_value.nil?

        value = new_value
      end

      return nil if value.prefixlen.zero?

      value.cidr
    end

    # Takes an address mask and protocol and converts the host portion to CIDR
    # notation.
    #
    # This takes into account you can negate a mask but follows all rules
    # defined in host_to_ip for the host/address part.
    #
    def self.host_to_mask(value, proto)
      match = value.match %r{(!)\s?(.*)$}
      return PuppetX::Firewall::Utility.host_to_ip(value, proto) unless match

      cidr = PuppetX::Firewall::Utility.host_to_ip(match[2], proto)
      return nil if cidr.nil?

      "#{match[1]} #{cidr}"
    end

    # Translate the symbolic names for icmp packet types to integers
    def self.icmp_name_to_number(value_icmp, protocol)
      if value_icmp.to_s.match?(%r{^\d+$})
        value_icmp.to_s
      elsif ['IPv4', 'iptables'].include?(protocol)
        # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
        case value_icmp
        when 'echo-reply' then '0'
        when 'destination-unreachable' then '3'
        when 'source-quench' then '4'
        when 'redirect' then '6'
        when 'echo-request' then '8'
        when 'router-advertisement' then '9'
        when 'router-solicitation' then '10'
        when 'time-exceeded' then '11'
        when 'parameter-problem' then '12'
        when 'timestamp-request' then '13'
        when 'timestamp-reply' then '14'
        when 'address-mask-request' then '17'
        when 'address-mask-reply' then '18'
        else nil
        end
      elsif ['IPv6', 'ip6tables'].include?(protocol)
        # https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
        case value_icmp
        when 'destination-unreachable' then '1'
        when 'too-big' then '2'
        when 'time-exceeded' then '3'
        when 'parameter-problem' then '4'
        when 'echo-request' then '128'
        when 'echo-reply' then '129'
        when 'router-solicitation' then '133'
        when 'router-advertisement' then '134'
        when 'neighbour-solicitation' then '135'
        when 'neighbour-advertisement' then '136'
        when 'redirect' then '137'
        else nil
        end
      else
        raise ArgumentError, "unsupported protocol family '#{protocol}'"
      end
    end

    # Convert log_level names to their respective numbers
    # https://www.iana.org/assignments/syslog-parameters/syslog-parameters.xhtml
    def self.log_level_name_to_number(value)
      if value.to_s.match?(%r{^[0-7]$})
        value.to_s
      else
        case value
        when 'panic' then '0'
        when 'alert' then '1'
        when 'crit' then '2'
        when 'err', 'error' then '3'
        when 'warn', 'warning' then '4'
        when 'not', 'notice' then '5'
        when 'info' then '6'
        when 'debug' then '7'
        else nil
        end
      end
    end

    # Validates the argument is int or hex, and returns valid hex
    # conversion of the value or nil otherwise.
    def self.to_hex32(value)
      begin
        value = Integer(value)
        return "0x#{value.to_s(16)}" if value.between?(0, 0xffffffff)
      rescue ArgumentError
        # pass
      end
      nil
    end

    # Accepts a valid mark or mark/mask and returns them in the valid
    # hexidecimal format.
    # Used for set_mark, match_mark, connmark
    def self.mark_mask_to_hex(value)
      match = value.to_s.match(%r{^(!\s)?([a-fA-F0-9x]+)\/?([a-fA-F0-9x]+)?})
      negation = '! '
      negation = '' if match[1].nil?
      mark = PuppetX::Firewall::Utility.to_hex32(match[2])
      return "#{negation}#{mark}/0xffffffff" if match[3].nil?

      mask = PuppetX::Firewall::Utility.to_hex32(match[3])
      "#{negation}#{mark}/#{mask}"
    end

    # Converts a given number to its protocol keyword
    # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    def self.proto_number_to_name(value)
      return value if %r{^(?:!\s)?([a-z])}.match?(value)

      match = value.to_s.match(%r{^(!\s)?(.*)})
      keyword = case match[2]
                when '1' then 'icmp'
                when '2' then 'igmp'
                when '4' then 'ipencap'
                when '6' then 'tcp'
                when '7' then 'cbt'
                when '17' then 'udp'
                when '47' then 'gre'
                when '50' then 'esp'
                when '51' then 'ah'
                when '89' then 'ospf'
                when '103' then 'pim'
                when '112' then 'vrrp'
                when '132' then 'sctp'
                else raise ArgumentError, "Unsupported proto number: #{value}"
                end
      "#{match[1]}#{keyword}"
    end

    # Converts a given number to its dscp class name
    # https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    def self.dscp_number_to_class(value)
      case value
      when '0x0a' then 'af11'
      when '0x0c' then 'af12'
      when '0x0e' then 'af13'
      when '0x12' then 'af21'
      when '0x14' then 'af22'
      when '0x16' then 'af23'
      when '0x1a' then 'af31'
      when '0x1c' then 'af32'
      when '0x1e' then 'af33'
      when '0x22' then 'af41'
      when '0x24' then 'af42'
      when '0x26' then 'af43'
      when '0x08' then 'cs1'
      when '0x10' then 'cs2'
      when '0x18' then 'cs3'
      when '0x20' then 'cs4'
      when '0x28' then 'cs5'
      when '0x30' then 'cs6'
      when '0x38' then 'cs7'
      when '0x2e' then 'ef'
      else nil
      end
    end
  end
end
