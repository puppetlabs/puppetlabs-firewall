require 'spec_helper_acceptance'

describe 'connlimit property' do
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
    it 'contains the connmark' do
      expect(result.stdout).to match(%r{-A INPUT -m connmark --mark 0x1 -m comment --comment "502 - connmark" -j REJECT --reject-with icmp-port-unreachable})
    end
  end
end
