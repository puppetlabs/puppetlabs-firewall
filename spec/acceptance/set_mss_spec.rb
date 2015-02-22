require 'spec_helper_acceptance'

describe 'firewall type', :unless => UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do
  describe 'set_mss' do
    context '50' do
      it 'applies' do
        pp = <<-EOS
          class { '::firewall': }
          firewall { 
            '502 - set_mss':
              proto   => 'tcp',
              jump    => 'TCPMSS',
              set_mss => '1360',
              chain   => 'FORWARD',
              table   => 'mangle',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
      end

      it 'should contain the rule' do
        shell('iptables-save') do |r|
          expect(r.stdout).to match(/-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "502 - set_mss" -j TCPMSS --set-mss 1360/)
        end
      end
    end
  end
end
