require 'spec_helper_acceptance'

describe 'firewall gid' do
  before :all do
    iptables_flush_all_tables
    ip6tables_flush_all_tables
  end

  describe "gid tests" do
    context 'gid set to root' do
      it 'applies' do
        pp = <<-EOS
          class { '::firewall': }
          firewall { '801 - test':
            chain => 'OUTPUT',
            action => accept,
            gid => 'root',
            proto => 'all',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)
      end

      it 'should contain the rule' do
         shell('iptables-save') do |r|
           expect(r.stdout).to match(/-A OUTPUT -m owner --gid-owner (0|root) -m comment --comment "801 - test" -j ACCEPT/)
         end
      end
    end

    context 'gid set to !root' do
      it 'applies' do
        pp = <<-EOS
          class { '::firewall': }
          firewall { '802 - test':
            chain => 'OUTPUT',
            action => accept,
            gid => '!root',
            proto => 'all',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)
      end

      it 'should contain the rule' do
         shell('iptables-save') do |r|
           expect(r.stdout).to match(/-A OUTPUT -m owner ! --gid-owner (0|root) -m comment --comment "802 - test" -j ACCEPT/)
         end
      end
    end

    context 'gid set to 0' do
      it 'applies' do
        pp = <<-EOS
          class { '::firewall': }
          firewall { '803 - test':
            chain => 'OUTPUT',
            action => accept,
            gid => '0',
            proto => 'all',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)
      end

      it 'should contain the rule' do
         shell('iptables-save') do |r|
           expect(r.stdout).to match(/-A OUTPUT -m owner --gid-owner (0|root) -m comment --comment "803 - test" -j ACCEPT/)
         end
      end
    end

    context 'gid set to !0' do
      it 'applies' do
        pp = <<-EOS
          class { '::firewall': }
          firewall { '804 - test':
            chain => 'OUTPUT',
            action => accept,
            gid => '!0',
            proto => 'all',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
        apply_manifest(pp, :catch_changes => do_catch_changes)
      end

      it 'should contain the rule' do
         shell('iptables-save') do |r|
           expect(r.stdout).to match(/-A OUTPUT -m owner ! --gid-owner (0|root) -m comment --comment "804 - test" -j ACCEPT/)
         end
      end
    end

  end

end
