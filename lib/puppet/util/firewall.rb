# Puppet Firewall Module
#
# Copyright (C) 2011 Bob.sh Limited
# Copyright (C) 2008 Camptocamp Association
# Copyright (C) 2007 Dmitri Priimak
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'socket'
require 'puppet/util/ipcidr'

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
end
