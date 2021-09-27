# @summary Main linux class, includes all other classes
#
# @param ensure
#   Controls the state of the ipv4 iptables service on your system. Valid options: 'running' or 'stopped'. Defaults to 'running'.
#
# @param ensure_v6
#   Controls the state of the ipv6 iptables service on your system. Valid options: 'running' or 'stopped'. Defaults to 'running'.
#
# @param pkg_ensure
#   Controls the state of the iptables package on your system. Valid options: 'installed' or 'latest'. Defaults to 'latest'.
#
# @param service_name
#   Specify the name of the IPv4 iptables service. Defaults defined in firewall::params.
#
# @param service_name_v6
#   Specify the name of the IPv6 iptables service. Defaults defined in firewall::params.
#
# @param package_name
#   Specify the platform-specific package(s) to install. Defaults defined in firewall::params.
#
# @param ebtables_manage
#   Controls whether puppet manages the ebtables package or not. If managed, the package will use the value of pkg_ensure.
#
# @api private
#
class firewall::linux (
  $ensure          = running,
  $ensure_v6       = undef,
  $pkg_ensure      = installed,
  $service_name    = $firewall::params::service_name,
  $service_name_v6 = $firewall::params::service_name_v6,
  $package_name    = $firewall::params::package_name,
  $ebtables_manage = false,
) inherits ::firewall::params {
  $enable = $ensure ? {
    'running' => true,
    'stopped' => false,
  }

  $_ensure_v6 = pick($ensure_v6, $ensure)

  $_enable_v6 = $_ensure_v6 ? {
    'running' => true,
    'stopped' => false,
  }

  if $facts['os']['name'] == 'Fedora' and versioncmp($facts['os']['release']['full'], '34') >= 0 {
    $_iptables_pkg = 'iptables-compat'
  } else{
    $_iptables_pkg = 'iptables'
  }

  package { $_iptables_pkg:
    ensure => $pkg_ensure,
  }

  if $ebtables_manage {
    package { 'ebtables':
      ensure => $pkg_ensure,
    }
  }

  case $facts['os']['name'] {
    'RedHat', 'CentOS', 'Fedora', 'Scientific', 'SL', 'SLC', 'Ascendos',
    'CloudLinux', 'PSBM', 'OracleLinux', 'OVS', 'OEL', 'Amazon', 'XenServer',
    'VirtuozzoLinux', 'Rocky': {
      class { "${title}::redhat":
        ensure          => $ensure,
        ensure_v6       => $_ensure_v6,
        enable          => $enable,
        enable_v6       => $_enable_v6,
        package_name    => $package_name,
        service_name    => $service_name,
        service_name_v6 => $service_name_v6,
        require         => Package[$_iptables_pkg],
      }
    }
    'Debian', 'Ubuntu': {
      class { "${title}::debian":
        ensure       => $ensure,
        enable       => $enable,
        package_name => $package_name,
        service_name => $service_name,
        require      => Package[$_iptables_pkg],
      }
    }
    'Archlinux': {
      class { "${title}::archlinux":
        ensure       => $ensure,
        enable       => $enable,
        package_name => $package_name,
        service_name => $service_name,
        require      => Package[$_iptables_pkg],
      }
    }
    'Gentoo': {
      class { "${title}::gentoo":
        ensure       => $ensure,
        enable       => $enable,
        package_name => $package_name,
        service_name => $service_name,
        require      => Package[$_iptables_pkg],
      }
    }
    default: {}
  }
}
