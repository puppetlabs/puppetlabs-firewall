require 'spec_helper_acceptance'

describe 'firewall inverting' do
  before :all do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  context "inverting rules" do
    it 'applies' do
      pp = <<-EOS
        class { '::firewall': }
        firewall { '601 disallow esp protocol':
          action => 'accept',
          proto  => '! esp',
        }
        firewall { '602 drop NEW external website packets with FIN/RST/ACK set and SYN unset':
          chain     => 'INPUT',
          state     => 'NEW',
          action    => 'drop',
          proto     => 'tcp',
          sport     => ['! http', '! 443'],
          source    => '! 10.0.0.0/8',
          tcp_flags => '! FIN,SYN,RST,ACK SYN',
        }
      EOS

      apply_manifest(pp, :catch_failures => true)
      apply_manifest(pp, :catch_changes => do_catch_changes)
    end

    it 'should contain the rules' do
      shell('iptables-save') do |r|
        expect(r.stdout).to match(/-A INPUT (-s !|! -s) (10\.0\.0\.0\/8|10\.0\.0\.0\/255\.0\.0\.0).*/)
        expect(r.stdout).to match(/-A INPUT.*(--sports !|! --sports) 80,443.*/)
        expect(r.stdout).to match(/-A INPUT.*-m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN.*/)
        expect(r.stdout).to match(/-A INPUT.*-j DROP/)
        expect(r.stdout).to match(/-A INPUT (! -p|-p !) esp -m comment --comment "601 disallow esp protocol" -j ACCEPT/)
      end
    end
  end
  context "inverting partial array rules" do
    it 'raises a failure' do
      pp = <<-EOS
        class { '::firewall': }
        firewall { '603 drop 80,443 traffic':
          chain     => 'INPUT',
          action    => 'drop',
          proto     => 'tcp',
          sport     => ['! http', '443'],
        }
      EOS

      apply_manifest(pp, :expect_failures => true) do |r|
        expect(r.stderr).to match(/is not prefixed/)
      end
    end
  end
end
