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
  install_pp = <<-PUPPETCODE
    $iptables_package_name = $facts['os']['family'] ? {
      'RedHat' => 'iptables-services',
      default  => 'iptables',
    }
    package { $iptables_package_name:
      ensure => 'latest',
    }
  PUPPETCODE
  LitmusHelper.instance.apply_manifest(install_pp)
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
    if os[:family] == 'redhat'
      pp = <<-PUPPETCODE
        package { 'iptables-services':
          ensure => 'latest',
        }
        package { 'policycoreutils':
          ensure => 'latest',
        }
      PUPPETCODE
      LitmusHelper.instance.apply_manifest(pp)
      LitmusHelper.instance.run_shell('yum install system-config-firewall-base -y')
      LitmusHelper.instance.run_shell('lokkit --default=server')
      LitmusHelper.instance.run_shell('service ip6tables restart')
      pre_setup
    end
    if os[:family] == 'debian' && os[:release].to_i == 10
      pp = <<-PUPPETCODE
        package { 'net-tools':
          ensure => 'latest',
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
