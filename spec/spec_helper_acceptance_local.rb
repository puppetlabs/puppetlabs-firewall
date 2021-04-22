# frozen_string_literal: true

require 'singleton'

class LitmusHelper
  include Singleton
  include PuppetLitmus
end

def iptables_flush_all_tables
  ['filter', 'nat', 'mangle', 'raw'].each do |t|
    expect(LitmusHelper.instance.run_shell("iptables -t #{t} -F").stderr).to eq('')
  end
end

def ip6tables_flush_all_tables
  ['filter', 'mangle'].each do |t|
    expect(LitmusHelper.instance.run_shell("ip6tables -t #{t} -F").stderr).to eq('')
  end
end

def install_iptables
  LitmusHelper.instance.run_shell('iptables -V')
rescue
  if os[:family] == 'redhat'
    LitmusHelper.instance.run_shell('yum install iptables-services -y')
  else
    LitmusHelper.instance.run_shell('apt-get install iptables -y')
  end
end

def iptables_version
  install_iptables
  x = LitmusHelper.instance.run_shell('iptables -V')
  x.stdout.split(' ')[1][1..-1]
end

def pre_setup
  LitmusHelper.instance.run_shell('mkdir -p /lib/modules/`uname -r`')
  LitmusHelper.instance.run_shell('depmod -a')
end

def update_profile_file
  LitmusHelper.instance.run_shell("sed -i '/mesg n/c\\test -t 0 && mesg n || true' ~/.profile")
  LitmusHelper.instance.run_shell("sed -i '/mesg n || true/c\\test -t 0 && mesg n || true' ~/.profile")
end

def fetch_os_name
  @facter_os_name ||= LitmusHelper.instance.run_shell('facter os.name').stdout.delete("\n").downcase
end

RSpec.configure do |c|
  # This flag is disabling test 'condition' from firewall_attributes_exceptions
  # because this test is failing on docker containers, but it's compatible with vmpooler machines
  # To enable tests on abs/vmpooler machines just set to `true` this flag
  c.filter_run_excluding condition_parameter_test: false
  c.before :suite do
    if ['centos', 'oraclelinux', 'scientific'].include?(fetch_os_name) && [6, 7].include?(os[:release].to_i)
      LitmusHelper.instance.run_shell('yum update -y')
      LitmusHelper.instance.run_shell('depmod -a')
      ['filter', 'nat', 'mangle', 'raw'].each do |t|
        LitmusHelper.instance.run_shell("modprobe iptable_#{t}")
        LitmusHelper.instance.run_shell("modprobe ip6table_#{t}")
      end
      LitmusHelper.instance.run_shell('touch /etc/sysconfig/iptables')
      LitmusHelper.instance.run_shell('touch /etc/sysconfig/ip6tables')
    end
    if os[:family] == 'debian'
      LitmusHelper.instance.run_shell('apt-get update -y')
      LitmusHelper.instance.run_shell('apt-get install kmod') if os[:release].to_i == 10
    end
    if fetch_os_name == 'centos' && os[:release].to_i == 8
      pp = <<-PUPPETCODE
        package { 'iptables-services':
          ensure => 'latest',
        }
        package { 'policycoreutils':
          ensure => 'latest',
        }
      PUPPETCODE
      LitmusHelper.instance.apply_manifest(pp)
    end
    if os[:family] == 'debian' && os[:release].to_i == 10
      pp = <<-PUPPETCODE
        package { 'net-tools':
          ensure   => 'latest',
        }
        PUPPETCODE
      LitmusHelper.instance.apply_manifest(pp)
      LitmusHelper.instance.run_shell('update-alternatives --set iptables /usr/sbin/iptables-legacy', expect_failures: true)
      LitmusHelper.instance.run_shell('update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy', expect_failures: true)
    end
    pp = <<-PUPPETCODE
      package { 'conntrack-tools':
        ensure => 'latest',
      }
      package { 'xtables-addons-common':
        ensure => 'latest',
      }
      package { 'iptables':
        ensure   => 'latest',
      }
    PUPPETCODE
    LitmusHelper.instance.apply_manifest(pp)
  end
end
