# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'firewall - duplicate comments' do
  before(:all) do
    update_profile_file if os[:family] == 'ubuntu' || os[:family] == 'debian'
  end

  after(:each) do
    iptables_flush_all_tables
  end

  context 'when a duplicate comment is found' do
    pp = <<-PUPPETCODE
    class { 'firewall': }
    resources { 'firewall':
      purge => true,
    }

    firewall { '550 destination':
      proto => tcp,
      dport => '550',
      jump => accept,
      destination => '192.168.2.0/24',
    }
    PUPPETCODE

    it 'raises an error' do
      run_shell('iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 551 -j ACCEPT -m comment --comment "550 destination"')
      run_shell('iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 552 -j ACCEPT -m comment --comment "550 destination"')

      apply_manifest(pp) do |r|
        expect(r.stderr).to include('Duplicate names have been found within your Firewalls. This prevents the module from working correctly and must be manually resolved.')
      end
    end
  end
end
