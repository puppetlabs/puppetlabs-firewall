require 'spec_helper_acceptance'

describe 'firewall type', :unless => UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do

  before(:all) do
    shell('iptables --flush; iptables -t nat --flush; iptables -t mangle --flush')
    shell('ip6tables --flush; ip6tables -t nat --flush; ip6tables -t mangle --flush')
  end

  describe 'set_mss' do
    context '1360' do
      it 'applies' do
        pp = <<-EOS
          class { '::firewall': }
          firewall {
            '502 - set_mss':
              proto     => 'tcp',
              tcp_flags => 'SYN,RST SYN',
              jump      => 'TCPMSS',
              set_mss   => '1360',
              mss       => '1361:1541',
              chain     => 'FORWARD',
              table     => 'mangle',
          }
        EOS

        apply_manifest(pp, :catch_failures => true)
      end

      it 'should contain the rule' do
        shell('iptables-save -t mangle') do |r|
          expect(r.stdout).to match(/-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "502 - set_mss" -m tcpmss --mss 1361:1541 -j TCPMSS --set-mss 1360/)
        end
      end
    end
  end

  if default['platform'] !~ /el-5/
    describe 'set_mss6' do
      context '1360' do
        it 'applies' do
          pp = <<-EOS
            class { '::firewall': }
            firewall {
              '502 - set_mss':
                proto     => 'tcp',
                tcp_flags => 'SYN,RST SYN',
                jump      => 'TCPMSS',
                set_mss   => '1360',
                mss       => '1361:1541',
                chain     => 'FORWARD',
                table     => 'mangle',
                provider  => 'ip6tables',
            }
          EOS

          apply_manifest(pp, :catch_failures => true)
        end

        it 'should contain the rule' do
          shell('ip6tables-save -t mangle') do |r|
            expect(r.stdout).to match(/-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -m comment --comment "502 - set_mss" -m tcpmss --mss 1361:1541 -j TCPMSS --set-mss 1360/)
          end
        end
      end
    end
  end

end
