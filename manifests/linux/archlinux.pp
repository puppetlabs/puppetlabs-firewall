# @summary 
#   Manages `iptables` and `ip6tables` services, and creates files used for persistence, on Arch Linux systems.
#
# @param ensure
#   Ensure parameter passed onto Service[] resources. Valid options: 'running' or 'stopped'. Defaults to 'running'.
#
# @param enable
#   Enable parameter passed onto Service[] resources. Defaults to 'true'.
#
# @param service_name
#   Specify the name of the IPv4 iptables service. Defaults defined in firewall::params.
#
# @param package_name
#   Specify the platform-specific package(s) to install. Defaults defined in firewall::params.
#
# @param package_ensure
#   Controls the state of the iptables package on your system. Valid options: 'present' or 'latest'. Defaults to 'latest'.
#
# @api private
#
class firewall::linux::archlinux (
  $ensure         = 'running',
  $enable         = true,
  $service_name   = $::firewall::params::service_name,
  $package_name   = $::firewall::params::package_name,
  $package_ensure = $::firewall::params::package_ensure,
) inherits ::firewall::params {
  if $package_name {
    package { $package_name:
      ensure => $package_ensure,
    }
  }

  service { $service_name:
    ensure    => $ensure,
    enable    => $enable,
    hasstatus => true,
  }

  file { '/etc/iptables/iptables.rules':
    ensure => present,
    before => Service[$service_name],
  }

  file { '/etc/iptables/ip6tables.rules':
    ensure => present,
    before => Service[$service_name],
  }
}
