require 'spec_helper_acceptance'

describe 'firewall type', :unless => UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do

  describe 'set_dscp' do
    context '50' do
      it 'applies' do
        pp = <<-EOS
          class { '::firewall': }
          firewall { 
            '502 - set_dscp hex':
              proto => 'tcp',
              jump => 'DSCP',
              set_dscp => '0x1A',
              action   => reject,

            '502 - set_dscp dec':
              proto => 'udp',
              jump => 'DSCP',
              set_dscp => '14',
              action   => reject,
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
      end

      it 'should contain the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(/-A POSTROUTING -p tcp -m tcp -j DSCP --set-dscp 0x1A/)
          expect(r.stdout).to match(/-A POSTROUTING -p udp -m udp -j DSCP --set-dscp 0x0E/)
        end
      end
    end
  end
end
