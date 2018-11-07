require 'spec_helper_acceptance'

# --bytecode is only supported by operatingsystems using nftables (in general Linux kernel 3.13, RedHat 7 (and derivates) with 3.10)
# Skipping those from which we know they would fail.
describe 'bytecode property', unless: (fact('osfamily') == 'RedHat' && fact('operatingsystemmajrelease') < '7') ||
                                      (fact('operatingsystem') == 'OracleLinux' && fact('operatingsystemmajrelease') <= '7') ||
                                      (fact('operatingsystem') == 'SLES' && fact('operatingsystemmajrelease') <= '11') do
  describe 'bytecode' do
    context '4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0' do
      pp = <<-PUPPETCODE
          class { '::firewall': }
          firewall { '102 - test':
            action   => 'accept',
            bytecode => '4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0',
            chain    => 'OUTPUT',
            proto    => 'all',
            table    => 'filter',
          }
      PUPPETCODE
      it 'applies' do
        apply_manifest(pp, catch_failures: true)
      end

      it 'contains the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(%r{-A OUTPUT -m bpf --bytecode "4,48 0 0 9,21 0 1 6,6 0 0 1,6 0 0 0" -m comment --comment "102 - test" -j ACCEPT})
        end
      end
    end
  end
end
