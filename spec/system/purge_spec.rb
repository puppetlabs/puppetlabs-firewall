require 'spec_helper_system'

describe "purge tests:" do
  context 'make sure duplicate existing rules get purged' do
    before :all do
      iptables_flush_all_tables

      shell('/sbin/iptables -A INPUT -s 1.2.1.2')
      shell('/sbin/iptables -A INPUT -s 1.2.1.2')
    end

    pp = <<-EOS
class { 'firewall': }
resources { 'firewall':
  purge => true,
}
    EOS

    context puppet_apply(pp) do
      its(:stderr) { should be_empty }
      its(:exit_code) { should == 2 }
    end

    context shell('/sbin/iptables-save') do
      its(:stdout) { should_not =~ /1\.2\.1\.2/ }
      its(:stderr) { should be_empty }
    end
  end

  context 'make sure rules get purged after applying new ones and not before' do
    before :all do
      iptables_flush_all_tables

      shell('/sbin/iptables -A INPUT -s 1.2.1.2')
      shell('/sbin/iptables -A INPUT -s 1.2.1.2')
    end

    pp = <<-EOS
      class my_fw::pre {
        Firewall {
          require => undef,
        }

        # Default firewall rules
        firewall { '000 accept all icmp':
          proto   => 'icmp',
          action  => 'accept',
        }->
        firewall { '001 accept all to lo interface':
          proto   => 'all',
          iniface => 'lo',
          action  => 'accept',
        }->
        firewall { '002 accept related established rules':
          proto   => 'all',
          state   => ['RELATED', 'ESTABLISHED'],
          action  => 'accept',
        }
      }
      class my_fw::post {
        firewall { '999 drop all':
          proto   => 'all',
          action  => 'drop',
          before  => undef,
        }
      }
      resources { "firewall":
        purge => true
      }
      Firewall {
        before  => Class['my_fw::post'],
        require => Class['my_fw::pre'],
      }
      class { ['my_fw::pre', 'my_fw::post']: }
      class { 'firewall': }
      firewall { '500 open up port 22':
        action => 'accept',
        proto => 'tcp',
        dport => 22,
      }
    EOS

    context puppet_apply(pp) do
      its(:stderr) { should be_empty }
      its(:exit_code) { should == 2 }
      it "create rules before purging" do
        list = subject.stdout.gsub(/.*ensure: (created|removed).*|.*Finished catalog run.*/, "\\1").split("\n")
        list.should eq(["created", "created", "created", "created", "created", "removed", "removed"]), subject.stdout
      end
    end
  end
end
