require 'spec_helper_acceptance'

describe 'firewall type', :unless => UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do

  describe 'match_mark' do
    context '0x1' do
      it 'applies' do
        pp = <<-EOS
          class { '::firewall': }
          firewall { '503 match_mark - test':
            proto      => 'all',
            match_mark => '0x1',
            action     => reject,
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
      end

      it 'should contain the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(/-A INPUT -m comment --comment "503 match_mark - test" -m mark --mark 0x1 -j REJECT --reject-with icmp-port-unreachable/)
        end
      end
    end
  end

  describe 'match_mark_ip6' do
    context '0x1' do
      it 'applies' do
        pp = <<-EOS
          class { '::firewall': }
          firewall { '503 match_mark ip6tables - test':
            proto      => 'all',
            match_mark => '0x1',
            action     => reject,
            provider => 'ip6tables',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
      end

      it 'should contain the rule' do
        shell('ip6tables-save') do |r|
          expect(r.stdout).to match(/-A INPUT -m comment --comment "503 match_mark ip6tables - test" -m mark --mark 0x1 -j REJECT --reject-with icmp6-port-unreachable/)
        end
      end
    end
  end
end
