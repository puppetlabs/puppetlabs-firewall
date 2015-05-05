require 'spec_helper_acceptance'

describe 'firewall type', :unless => UNSUPPORTED_PLATFORMS.include?(fact('osfamily')) do

  
  before(:all) do
    shell('iptables --flush; iptables -t nat --flush; iptables -t mangle --flush')
    shell('ip6tables --flush; ip6tables -t nat --flush; ip6tables -t mangle --flush')
  end

  if default['platform'] =~ /ubuntu-1404/ or default['platform'] =~ /debian-7/ or default['platform'] =~ /debian-8/ or default['platform'] =~ /el-7/
    describe "time tests ipv4" do
      context 'set all time parameters' do
        it 'applies' do
          pp = <<-EOS
            class { '::firewall': }
            firewall { '805 - test':
              proto              => tcp,
              dport              => '8080',
              action             => accept,
              chain              => 'OUTPUT',
              date_start         => '2016-01-19T04:17:07',
              date_stop          => '2038-01-19T04:17:07',
              time_start         => '6:00',
              time_stop          => '17:00:00',
              month_days         => '7',
              week_days          => 'Tue',
              kernel_timezone    => true,
            }
          EOS

          apply_manifest(pp, :catch_failures => true)
          unless fact('selinux') == 'true'
            apply_manifest(pp, :catch_changes => true)
          end
        end

        it 'should contain the rule' do
           shell('iptables-save') do |r|
             expect(r.stdout).to match(/-A OUTPUT -p tcp -m multiport --dports 8080 -m comment --comment "805 - test" -m time --timestart 06:00:00 --timestop 17:00:00 --monthdays 7 --weekdays Tue --datestart 2016-01-19T04:17:07 --datestop 2038-01-19T04:17:07 --kerneltz -j ACCEPT/)
           end
        end
      end
    end

    describe "time tests ipv6" do
      context 'set all time parameters' do
        it 'applies' do
          pp = <<-EOS
            class { '::firewall': }
            firewall { '805 - test':
              proto              => tcp,
              dport              => '8080',
              action             => accept,
              chain              => 'OUTPUT',
              date_start         => '2016-01-19T04:17:07',
              date_stop          => '2038-01-19T04:17:07',
              time_start         => '6:00',
              time_stop          => '17:00:00',
              month_days         => '7',
              week_days          => 'Tue',
              kernel_timezone    => true,
              provider           => 'ip6tables',
            }
          EOS

          apply_manifest(pp, :catch_failures => true)
          unless fact('selinux') == 'true'
            apply_manifest(pp, :catch_changes => true)
          end
        end

        it 'should contain the rule' do
           shell('ip6tables-save') do |r|
             expect(r.stdout).to match(/-A OUTPUT -p tcp -m multiport --dports 8080 -m comment --comment "805 - test" -m time --timestart 06:00:00 --timestop 17:00:00 --monthdays 7 --weekdays Tue --datestart 2016-01-19T04:17:07 --datestop 2038-01-19T04:17:07 --kerneltz -j ACCEPT/)
           end
        end
      end
    end
  end
end
