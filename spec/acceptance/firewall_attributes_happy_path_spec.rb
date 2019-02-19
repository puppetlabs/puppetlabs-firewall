require 'spec_helper_acceptance'

describe 'firewall attribute testing, happy path' do
  before :all do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  describe 'attributes test' do
    before(:all) do
      pp = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '501 - connlimit':
            proto           => tcp,
            dport           => '2222',
            connlimit_above => '10',
            connlimit_mask  => '24',
            action          => reject,
          }
          firewall { '502 - connmark':
            proto    => 'all',
            connmark => '0x1',
            action   => reject,
          }
          firewall { '556 - source':
            proto  => tcp,
            port   => '556',
            action => accept,
            source => '192.168.2.0/24',
          }
          firewall { '557 - source negated':
            proto  => tcp,
            port   => '557',
            action => accept,
            source => '! 192.168.2.0/24',
          }
          firewall { '801 - gid root':
            chain => 'OUTPUT',
            action => accept,
            gid => 'root',
            proto => 'all',
          }
          firewall { '802 - gid root negated':
            chain => 'OUTPUT',
            action => accept,
            gid => '!root',
            proto => 'all',
          }
          firewall { '803 - uid 0':
            chain => 'OUTPUT',
            action => accept,
            uid => '0',
            proto => 'all',
          }
          firewall { '804 - uid 0 negated':
            chain => 'OUTPUT',
            action => accept,
            uid => '!0',
            proto => 'all',
          }
      PUPPETCODE
      apply_manifest(pp, catch_failures: true)
      apply_manifest(pp, catch_changes: do_catch_changes)
    end
    let(:result) { shell('iptables-save') }

    it 'contains the connlimit and connlimit_mask rule' do
      expect(result.stdout).to match(
        %r{-A INPUT -p tcp -m multiport --dports 2222 -m connlimit --connlimit-above 10 --connlimit-mask 24 (--connlimit-saddr )?-m comment --comment "501 - connlimit" -j REJECT --reject-with icmp-port-unreachable}, # rubocop:disable Metrics/LineLength
      )
    end
    it 'contains connmark' do
      expect(result.stdout).to match(%r{-A INPUT -m connmark --mark 0x1 -m comment --comment "502 - connmark" -j REJECT --reject-with icmp-port-unreachable})
    end
    it 'source is set' do
      expect(result.stdout).to match(%r{-A INPUT -s 192.168.2.0\/(24|255\.255\.255\.0) -p tcp -m multiport --ports 556 -m comment --comment "556 - source" -j ACCEPT})
    end
    it 'source is negated' do
      expect(result.stdout).to match(%r{-A INPUT (! -s|-s !) 192.168.2.0\/(24|255\.255\.255\.0) -p tcp -m multiport --ports 557 -m comment --comment "557 - source negated" -j ACCEPT})
    end
    it 'gid set to root' do
      expect(result.stdout).to match(%r{-A OUTPUT -m owner --gid-owner (0|root) -m comment --comment "801 - gid root" -j ACCEPT})
    end
    it 'gid set to root negated' do
      expect(result.stdout).to match(%r{-A OUTPUT -m owner ! --gid-owner (0|root) -m comment --comment "802 - gid root negated" -j ACCEPT})
    end
    it 'uid set to 0' do
      expect(result.stdout).to match(%r{-A OUTPUT -m owner --uid-owner (0|root) -m comment --comment "803 - uid 0" -j ACCEPT})
    end
    it 'uid set to 0 negated' do
      expect(result.stdout).to match(%r{-A OUTPUT -m owner ! --uid-owner (0|root) -m comment --comment "804 - uid 0 negated" -j ACCEPT})
    end
  end
end
