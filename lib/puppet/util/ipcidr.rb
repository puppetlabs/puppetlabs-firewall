require 'ipaddr'

# IPCidr object wrapper for IPAddr
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
        len = self.prefixlen
        if ( @family == Socket::AF_INET && len == IN4MASK ) || ( @family == Socket::AF_INET6 && len == IN6MASK ) 
          cidr = self.to_s
        else
          cidr = sprintf("%s/%s", self.to_s, len)
        end
      end
    end
  end
end
