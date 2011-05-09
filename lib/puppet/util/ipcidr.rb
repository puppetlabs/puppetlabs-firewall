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

require 'ipaddr'

module Puppet
  module Util
    class IPCidr < IPAddr
  
      def netmask
        _to_string(@mask_addr)
      end

      def prefixlen
        m = case @family
            when Socket::AF_INET
              IN4MASK
            when Socket::AF_INET6
              IN6MASK
            else
              raise "unsupported address family"
            end
        return $1.length if /\A(1*)(0*)\z/ =~ (@mask_addr & m).to_s(2)
        raise "bad addr_mask format"
      end

      def cidr
        cidr = sprintf("%s/%s", self.to_s, self.prefixlen)
        cidr
      end
    end
  end
end
