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
class firewall::service inherits firewall {

  case $ensure {
    /^(running|stopped)$/: {
      # Do nothing.
    }
    default: {
      fail("${module_name}: Ensure value '${ensure}' is not supported")
    }
  }

  case $::kernel {
    'Linux': {
      class { "${module_name}::linux":
        ensure       => $ensure,
        service_name => $service_name,
        package_name => $package_name,
      }
    }
    default: {
      fail("${module_name}: Kernel '${::kernel}' is not currently supported")
    }
  }
}

