# = Class: firewall::linux
#
# Installs the `iptables` package for Linux operating systems and includes
# the appropriate sub-class for any distribution specific services and
# additional packages.
#
# == Parameters:
#
# [*ensure*]
#   Ensure parameter passed onto Service[] resources. When `running` the
#   service will be started on boot, and when `stopped` it will not.
#   Default: running
#
class firewall::linux (
  $ensure = running
) {
  $enable = $ensure ? {
    running => true,
    stopped => false,
  }

  $uses_firewalld = $::operatingsystem == 'Fedora' and $::operatingsystemrelease == '18'

  if $uses_firewalld {
    $package_name = 'iptables-services'
  } else {
    $package_name = 'iptables'
  }

  package { $package_name:
    ensure => present,
  }

  case $::operatingsystem {
    'RedHat', 'CentOS', 'Fedora': {
      class { "${title}::redhat":
        ensure  => $ensure,
        enable  => $enable,
        require => Package[$package_name],
      }
    }
    'Debian', 'Ubuntu': {
      class { "${title}::debian":
        ensure  => $ensure,
        enable  => $enable,
        require => Package[$package_name],
      }
    }
    'Archlinux': {
      class { "${title}::archlinux":
        ensure  => $ensure,
        enable  => $enable,
        require => Package[$package_name],
      }
    }
    default: {}
  }
}
