require 'puppet_x'

module PuppetX::Firewall
  class Utility

    # Save any current iptables changes so they are retained upon restart
    def self.persist_iptables(context, name, protocol)
      os_key = Facter.value('os')['family']
      cmd = case os_key
            when 'RedHat'
              case protocol
              when 'IPv4'
                ['/usr/libexec/iptables/iptables.init', 'save']
              when 'IPv6'
                ['/usr/libexec/iptables/ip6tables.init', 'save']
              end
            when 'Debian'
              fact = Facter.fact(:iptables_persistent_version)
              fact.flush if fact.respond_to?(:flush)
              persist_ver = fact.value

              case protocol
              when 'IPv4', 'IPv6'
                if persist_ver && Puppet::Util::Package.versioncmp(persist_ver, '1.0') > 0
                  ['/usr/sbin/service', 'netfilter-persistent', 'save']
                else
                  ['/usr/sbin/service', 'iptables-persistent', 'save']
                end
              end
            when 'Archlinux'
              case protocol
              when 'IPv4'
                ['/bin/sh', '-c', '/usr/sbin/iptables-save > /etc/iptables/iptables.rules']
              when 'IPv6'
                ['/bin/sh', '-c', '/usr/sbin/ip6tables-save > /etc/iptables/ip6tables.rules']
              end
            when 'Suse'
              case protocol
              when 'IPv4'
                ['/bin/sh', '-c', '/usr/sbin/iptables-save > /etc/sysconfig/iptables']
              end
            else
                Catch unsupported OSs
              debug('firewall: Rule persistence is not supported for this type/OS')
              return
            end

    #   require 'pry'; binding.pry;

      begin
        context.notice("Ensuring changes to '#{name}' persist")
        Puppet::Provider.execute(cmd)
      rescue Puppet::ExecutionFailure => detail
        warning("Unable to persist firewall rules: #{detail}")
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
  end
end
