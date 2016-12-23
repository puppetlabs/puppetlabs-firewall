# = Class: firewall
#
# Manages packages and services required by the firewall type/provider.
#
# This class includes the appropriate sub-class for your operating system,
# where supported.
#
# == Parameters:
#
# [*ensure*]
#   Ensure parameter passed onto Service[] resources.
#   Default: running
#
class firewall (
  $ensure          = running,
  $pkg_ensure      = present,
  $service_name    = $::firewall::params::service_name,
  $service_name_v6 = $::firewall::params::service_name_v6,
  $package_name    = $::firewall::params::package_name,
) inherits ::firewall::params {
  case $ensure {
    /^(running|stopped)$/: {
      # Do nothing.
    }
    default: {
      fail("${title}: Ensure value '${ensure}' is not supported")
    }
  }

  case $::kernel {
    'Linux': {
      class { "${title}::linux":
        ensure          => $ensure,
        pkg_ensure      => $pkg_ensure,
        service_name    => $service_name,
        service_name_v6 => $service_name_v6,
        package_name    => $package_name,
      }
      contain "${title}::linux"
    }
    'FreeBSD': {
    }
    default: {
      fail("${title}: Kernel '${::kernel}' is not currently supported")
    }
  }
}
