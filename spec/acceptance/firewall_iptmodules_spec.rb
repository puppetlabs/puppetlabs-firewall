require 'spec_helper_acceptance'

describe 'firewall iptmodules' do
  before :all do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  describe 'iptables ipt_modules tests' do
    context 'when all the modules with multiple args' do
      pp1 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '801 - ipt_modules tests':
            proto              => tcp,
            dport              => '8080',
            action             => reject,
            chain              => 'OUTPUT',
            uid                => 0,
            gid                => 404,
            src_range          => "90.0.0.1-90.0.0.2",
            dst_range          => "100.0.0.1-100.0.0.2",
            src_type           => 'LOCAL',
            dst_type           => 'UNICAST',
            physdev_in         => "eth0",
            physdev_out        => "eth1",
            physdev_is_bridged => true,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp1, catch_failures: true)
        apply_manifest(pp1, catch_changes: do_catch_changes)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A OUTPUT -p tcp -m physdev\s+--physdev-in eth0 --physdev-out eth1 --physdev-is-bridged -m iprange --src-range 90.0.0.1-90.0.0.2\s+--dst-range 100.0.0.1-100.0.0.2 -m owner --uid-owner (0|root) --gid-owner 404 -m multiport --dports 8080 -m addrtype --src-type LOCAL --dst-type UNICAST -m comment --comment "801 - ipt_modules tests" -j REJECT --reject-with icmp-port-unreachable}) # rubocop:disable Metrics/LineLength
        end
      end
    end

    context 'when all the modules with single args' do
      pp2 = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '802 - ipt_modules tests':
            proto              => tcp,
            dport              => '8080',
            action             => reject,
            chain              => 'OUTPUT',
            gid                => 404,
            dst_range          => "100.0.0.1-100.0.0.2",
            dst_type           => 'UNICAST',
            physdev_out        => "eth1",
            physdev_is_bridged => true,
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp2, catch_failures: true)
        apply_manifest(pp2, catch_changes: do_catch_changes)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A OUTPUT -p tcp -m physdev\s+--physdev-out eth1 --physdev-is-bridged -m iprange --dst-range 100.0.0.1-100.0.0.2 -m owner --gid-owner 404 -m multiport --dports 8080 -m addrtype --dst-type UNICAST -m comment --comment "802 - ipt_modules tests" -j REJECT --reject-with icmp-port-unreachable}) # rubocop:disable Metrics/LineLength
        end
      end
    end
  end

  describe 'ip6tables ipt_modules tests', unless: (os[:family] == 'redhat' && os[:release].start_with?('5', '6')) || (os[:family] == 'sles') do
    context 'when all the modules with multiple args' do
      pp3 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '801 - ipt_modules tests':
                proto              => tcp,
                dport              => '8080',
                action             => reject,
                chain              => 'OUTPUT',
                provider           => 'ip6tables',
                uid                => 0,
                gid                => 404,
                src_range          => "2001::-2002::",
                dst_range          => "2003::-2004::",
                src_type           => 'LOCAL',
                dst_type           => 'UNICAST',
                physdev_in         => "eth0",
                physdev_out        => "eth1",
                physdev_is_bridged => true,
              }
        PUPPETCODE
      it 'applies' do
        apply_manifest(pp3, catch_failures: true)
        apply_manifest(pp3, catch_changes: do_catch_changes)
      end

      it 'contains the rule' do
        shell('ip6tables-save') do |r|
          expect(r.stdout).to match(%r{-A OUTPUT -p tcp -m physdev\s+--physdev-in eth0 --physdev-out eth1 --physdev-is-bridged -m iprange --src-range 2001::-2002::\s+--dst-range 2003::-2004:: -m owner --uid-owner (0|root) --gid-owner 404 -m multiport --dports 8080 -m addrtype --src-type LOCAL --dst-type UNICAST -m comment --comment "801 - ipt_modules tests" -j REJECT --reject-with icmp6-port-unreachable}) # rubocop:disable Metrics/LineLength
        end
      end
    end

    context 'when all the modules with single args' do
      pp4 = <<-PUPPETCODE
              class { '::firewall': }
              firewall { '802 - ipt_modules tests':
                proto              => tcp,
                dport              => '8080',
                action             => reject,
                chain              => 'OUTPUT',
                provider           => 'ip6tables',
                gid                => 404,
                dst_range          => "2003::-2004::",
                dst_type           => 'UNICAST',
                physdev_out        => "eth1",
                physdev_is_bridged => true,
              }
        PUPPETCODE
      it 'applies' do
        apply_manifest(pp4, catch_failures: true)
        apply_manifest(pp4, catch_changes: do_catch_changes)
      end

      it 'contains the rule' do
        shell('ip6tables-save') do |r|
          expect(r.stdout).to match(%r{-A OUTPUT -p tcp -m physdev\s+--physdev-out eth1 --physdev-is-bridged -m iprange --dst-range 2003::-2004:: -m owner --gid-owner 404 -m multiport --dports 8080 -m addrtype --dst-type UNICAST -m comment --comment "802 - ipt_modules tests" -j REJECT --reject-with icmp6-port-unreachable}) # rubocop:disable Metrics/LineLength
        end
      end
    end
  end
end
