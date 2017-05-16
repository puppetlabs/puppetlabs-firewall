require 'spec_helper_acceptance'

describe 'nflog on older OSes', :if => fact('iptables_version') < '1.3.7' do
  let(:pp) { <<-EOS
        class {'::firewall': }
        firewall { '503 - test':
          jump  => 'NFLOG',
          proto => 'all',
          nflog_group => 3,
        }
      EOS
  }
  it 'should throw an error' do
    apply_manifest(pp, :acceptable_error_codes => [0])
  end
end

describe 'nflog', :unless => fact('iptables_version') < '1.3.7' do
  describe 'nflog_group' do

    let(:group) { 3 }

    it 'applies' do
      pp = <<-EOS
        class {'::firewall': }
        firewall { '503 - test':
          jump  => 'NFLOG',
          proto => 'all',
          nflog_group => #{group},
        }
      EOS
      apply_manifest(pp, :catch_failures => true)
    end

    it 'contains the rule' do
      shell('iptables-save') do |r|
        expect(r.stdout).to match(/NFLOG --nflog-group #{group}/)
      end
    end
  end

  describe 'nflog_prefix' do

    let(:prefix) { "TEST PREFIX" }

    it 'applies' do
      pp = <<-EOS
      class {'::firewall': }
      firewall { '503 - test':
        jump  => 'NFLOG',
        proto => 'all',
        nflog_prefix => '#{prefix}',
      }
    EOS
      apply_manifest(pp, :catch_failures => true)
    end

    it 'contains the rule' do
      shell('iptables-save') do |r|
        expect(r.stdout).to match(/NFLOG --nflog-prefix +"#{prefix}"/)
      end
    end
  end

  describe 'nflog_range' do

    let(:range) { 16 }

    it 'applies' do
      pp = <<-EOS
        class {'::firewall': }
        firewall { '503 - test':
          jump  => 'NFLOG',
          proto => 'all',
          nflog_range => #{range},
        }
      EOS
      apply_manifest(pp, :catch_failures => true)
    end

    it 'contains the rule' do
      shell('iptables-save') do |r|
        expect(r.stdout).to match(/NFLOG --nflog-range #{range}/)
      end
    end
  end

  describe 'nflog_threshold' do

    let(:threshold) { 2 }

    it 'applies' do
      pp = <<-EOS
        class {'::firewall': }
        firewall { '503 - test':
          jump  => 'NFLOG',
          proto => 'all',
          nflog_threshold => #{threshold},
        }
      EOS
      apply_manifest(pp, :catch_failures => true)
    end

    it 'contains the rule' do
      shell('iptables-save') do |r|
        expect(r.stdout).to match(/NFLOG --nflog-threshold #{threshold}/)
      end
    end
  end

  describe 'multiple rules' do
    let(:threshold) { 2 }
    let(:group) { 3 }

    it 'applies' do
      pp = <<-EOS
        class {'::firewall': }
        firewall { '503 - test':
          jump  => 'NFLOG',
          proto => 'all',
          nflog_threshold => #{threshold},
          nflog_group => #{group}
        }
      EOS
      apply_manifest(pp, :catch_failures => true)
    end

    it 'contains the rules' do
      shell('iptables-save') do |r|
        expect(r.stdout).to match(/NFLOG --nflog-group #{group} --nflog-threshold #{threshold}/)
      end
    end

  end
end
