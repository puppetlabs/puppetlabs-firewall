# @summary 
# Performs the basic setup tasks required for using the firewall resources.
#
# At the moment this takes care of:
#
# iptables-persistent package installation
# Include the firewall class for nodes that need to use the resources in this module:
#
# @example
#   class { 'firewall': }
#
# @param ensure
#   Controls the state of the ipv4 iptables service on your system. Valid options: 'running' or 'stopped'.
#
# @param ensure_v6
#   Controls the state of the ipv6 iptables service on your system. Valid options: 'running' or 'stopped'.
#
# @param pkg_ensure
#   Controls the state of the iptables package on your system. Valid options: 'present' or 'latest'.
#
# @param service_name
#   Specify the name of the IPv4 iptables service.
#
# @param service_name_v6
#   Specify the name of the IPv6 iptables service.
#
# @param package_name
#   Specify the platform-specific package(s) to install.
#
# @param ebtables_manage
#   Controls whether puppet manages the ebtables package or not. If managed, the package will use the value of pkg_ensure.
#
class firewall (
  $ensure          = running,
  $ensure_v6       = undef,
  $pkg_ensure      = present,
  $service_name    = $::firewall::params::service_name,
  $service_name_v6 = $::firewall::params::service_name_v6,
  $package_name    = $::firewall::params::package_name,
  $ebtables_manage = false,
) inherits ::firewall::params {
  $_ensure_v6 = pick($ensure_v6, $ensure)

  case $ensure {
    /^(running|stopped)$/: {
      # Do nothing.
    }
    default: {
      fail("${title}: Ensure value '${ensure}' is not supported")
    }
  }

  if $ensure_v6 {
    case $ensure_v6 {
      /^(running|stopped)$/: {
        # Do nothing.
      }
      default: {
        fail("${title}: ensure_v6 value '${ensure_v6}' is not supported")
      }
    }
  }

  case $::kernel {
    'Linux': {
      class { "${title}::linux":
        ensure          => $ensure,
        ensure_v6       => $_ensure_v6,
        pkg_ensure      => $pkg_ensure,
        service_name    => $service_name,
        service_name_v6 => $service_name_v6,
        package_name    => $package_name,
        ebtables_manage => $ebtables_manage,
      }
      contain "${title}::linux"
    }
    'FreeBSD', 'windows': {
    }
    default: {
      fail("${title}: Kernel '${::kernel}' is not currently supported")
    }
  }
}
