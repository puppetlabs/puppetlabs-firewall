require 'socket'
require 'resolv'
require 'puppet/util/ipcidr'

# Util module for puppetlabs-firewall
module Puppet::Util::Firewall
  # Translate the symbolic names for icmp packet types to integers
  def icmp_name_to_number(value_icmp)
    if value_icmp =~ /\d{1,2}$/
      value_icmp
    else
      case value_icmp
        when "echo-reply" then "0"
        when "destination-unreachable" then "3"
        when "source-quench" then "4"
        when "redirect" then "6"
        when "echo-request" then "8"
        when "router-advertisement" then "9"
        when "router-solicitation" then "10"
        when "time-exceeded" then "11"
        when "parameter-problem" then "12"
        when "timestamp-request" then "13"
        when "timestamp-reply" then "14"
        when "address-mask-request" then "17"
        when "address-mask-reply" then "18"
        else nil
      end
    end
  end

  # Convert log_level names to their respective numbers
  def log_level_name_to_number(value)
    #TODO make this 0-7 only
    if value =~ /\d/
      value
    else
      case value
        when "panic" then "0"
        when "alert" then "1"
        when "crit" then "2"
        when "err" then "3"
        when "error" then "3"
        when "warn" then "4"
        when "warning" then "4"
        when "not" then "5"
        when "notice" then "5"
        when "info" then "6"
        when "debug" then "7"
        else nil
      end
    end
  end

  # This method takes a string and attempts to convert it to a port number
  # if valid.
  #
  # If the string already contains a port number or perhaps a range of ports
  # in the format 22:1000 for example, it simply returns the string and does
  # nothing.
  def string_to_port(value)
    if value.kind_of?(String)
      if value.match(/^\d+(-\d+)?$/)
        return value
      else
        return Socket.getservbyname(value).to_s
      end
    else
      Socket.getservbyname(value)
    end
  end

  def host_to_ip(value)
    begin
      Puppet::Util::IPCidr.new(value).cidr
    rescue
      Puppet::Util::IPCidr.new(Resolv.getaddress(value)).cidr
    end
  end
end
