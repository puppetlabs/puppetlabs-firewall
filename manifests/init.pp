# Class: firewall
#
# This module manages firewalls.
#
# Parameters:
#
# Actions:
#
# Sets up some resources to manage iptables configs on Linux.
# on various flavours of Linux.
# 1. A firewall-persist exec to make rebooting safe.
# 2. Debian hates you and has no provisions for managing iptables by default.  Fixes that.
#
# Requires:
#
# Sample Usage:
#
# Put this in site.pp to ensure proper operation:
# Firewall {
#     notify  => Exec['firewall-persist'],
# }
#
class firewall {

  Exec {
    path => [ '/bin', '/sbin' ],
  }

  case $kernel {
    'Linux': {

      case $operatingsystem {
        Debian: {
          ## The iptables in Lenny definitely works.
          ## Older versions not tested.
          ## Meanwhile, Debian 'testing' will break.
          if $lsbmajdistrelease >= 5 {
            $firewall_supports_ipv6 = true
          }

          file { '/etc/iptables':
            ensure => directory,
            group  => 'root',
            mode   => '0750',
            owner  => 'root',
          }

          $ip6tables_rules = '/etc/iptables/rules.v6'

          ## Squeeze 'iptables-persistent' package has unique rules file.
          case $lsbmajdistrelease {
            6:       { $iptables_rules  = '/etc/iptables/rules' }
            default: { $iptables_rules  = '/etc/iptables/rules.v4' }
          }

          ## Lenny has no intrinsic ability to manage iptables persistence.
          ## So we magick it up here. Note: this persists IPv6 rules..
          if $lsbmajdistrelease <= 5 {
            file { '/etc/init.d/iptables-persistent':
              content => template('firewall/debian/iptables-persistent.erb'),
              group   => 'root',
              mode    => '0755',
              owner   => 'root',
            }

            $service_persist_requires = File['/etc/init.d/iptables-persistent']
          }
          else {
            package { 'iptables-persistent':
              ensure => present,
            }
            $service_persist_requires = Package['iptables-persistent']
          }

          service { 'iptables-persistent':
            enable  => true,
            require => $service_persist_requires,
          }

          ## Squeeze 'iptables-persistent' package is ignorant of IPv6.
          ## So, we slap in a separate IPv6 persistence script just for it.
          if $firewall_supports_ipv6 {

            file { $ip6tables_rules:
              group   => 'root',
              mode    => '0600',
              owner   => 'root',
              require => Exec['firewall-persist'],
            }

            if $lsbmajdistrelease == 6 {
              file { '/etc/init.d/ip6tables-persistent':
                content => template('firewall/debian/iptables-persistent.erb'),
                group   => 'root',
                mode    => '0755',
                owner   => 'root',
              }

              service { 'ip6tables-persistent':
                enable  => true,
                require => File['/etc/init.d/ip6tables-persistent'],
              }

            }
          }
        }
        ## Since this RedHat section makes assumptions about release version numbering
        ## It only makes sense for RHEL-alike OSes.
        RedHat,CentOS,CloudLinux: {
          ## ip6tables in CentOS 5.x does not support comments
          ## The provider needs comments, so we play dumb on older versions.
          if $lsbmajdistrelease >= 6 {
            $firewall_supports_ipv6 = true
          }

          $ip6tables_rules = '/etc/sysconfig/ip6tables'
          $iptables_rules  = '/etc/sysconfig/iptables'

          package { 'iptables':
            ensure => present,
          }

          service { 'iptables':
            enable => true,
          }

          package { 'iptables-ipv6':
            ensure => present,
          }

          service { 'ip6tables':
            enable => true,
          }

          ## RHEL supports IPv6, but older versions do not support comments.
          ## The provider requires comments, so we just force a REJECT on all filter chains there.
          if $firewall_supports_ipv6 {
            file { $ip6tables_rules:
              group   => 'root',
              mode    => '0600',
              owner   => 'root',
              require => Exec['firewall-persist'],
            }
          }
          else {
            file { $ip6tables_rules:
              content => template('firewall/redhat/ip6tables.erb'),
              group   => 'root',
              mode    => '0600',
              owner   => 'root',
              require => Exec['firewall-persist'],
            }
            exec { 'set-ipv6-iptables-policy':
              command     => '/sbin/service ip6tables restart',
              subscribe   => File[$ip6tables_rules],
              refreshonly => true,
            }
            warning("On '${lsbdistdescription}', the firewall provider does not support ip6tables. Setting a default REJECT rule")
          }
        }
        default: { fail("$operatingsystem is not supported by the firewall class") }
      }

      file { $iptables_rules:
        group   => 'root',
        mode    => '0600',
        owner   => 'root',
        require => Exec['firewall-persist'],
      }

      ## Tell site.pp (see docs) to notify this exec for all firewall rules
      ## Thus, ensuring good rules at boot time.
      exec { 'firewall-persist':
        command     => "iptables-save |sed -e '/^#/ d' > ${iptables_rules}; ip6tables-save |sed -e '/^#/ d' > ${ip6tables_rules}",
        refreshonly => true,
      }

    }
    default: {
      warning("'firewall-persist' is currently a noop on ${kernel}")
      exec { 'firewall-persist':
        command     => '/bin/true',
        refreshonly => true,
      }
    }
  }
}
