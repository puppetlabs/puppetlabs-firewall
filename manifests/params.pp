# @summary Provides defaults for the Apt module parameters.
# 
# @api private
#
class firewall::params {
  $package_ensure = 'present'
  case $::osfamily {
    'RedHat': {
      case $::operatingsystem {
        'Amazon': {
          $service_name = 'iptables'
          $service_name_v6 = 'ip6tables'
          $package_name = undef
          $sysconfig_manage = true
        }
        'Fedora': {
          $service_name = 'iptables'
          $service_name_v6 = 'ip6tables'
          if versioncmp($::operatingsystemrelease, '15') >= 0 {
            $package_name = 'iptables-services'
          } else {
            $package_name = undef
          }
          $sysconfig_manage = true
        }
        default: {
          if versioncmp($::operatingsystemrelease, '8.0') >= 0 {
            $service_name = ['iptables', 'nftables']
            $service_name_v6 = 'ip6tables'
            $package_name = ['iptables-services', 'nftables']
            $sysconfig_manage = false
          } elsif versioncmp($::operatingsystemrelease, '7.0') >= 0 {
            $service_name = 'iptables'
            $service_name_v6 = 'ip6tables'
            $package_name = 'iptables-services'
            $sysconfig_manage = true
          } else {
            $service_name = 'iptables'
            $service_name_v6 = 'ip6tables'
            $package_name = 'iptables-ipv6'
            $sysconfig_manage = true
          }
        }
      }
    }
    'Debian': {
      $service_name_v6 = undef
      case $::operatingsystem {
        'Debian': {
          if versioncmp($::operatingsystemrelease, 'unstable') >= 0 {
            $service_name = 'netfilter-persistent'
            $package_name = 'netfilter-persistent'
          } elsif versioncmp($::operatingsystemrelease, '8.0') >= 0 {
            $service_name = 'netfilter-persistent'
            $package_name = 'iptables-persistent'
          } else {
            $service_name = 'iptables-persistent'
            $package_name = 'iptables-persistent'
          }

        }
        'Ubuntu': {
          if versioncmp($::operatingsystemrelease, '14.10') >= 0 {
            $service_name = 'netfilter-persistent'
            $package_name = 'iptables-persistent'
          } else {
            $service_name = 'iptables-persistent'
            $package_name = 'iptables-persistent'
          }

        }
        default: {
          $service_name = 'iptables-persistent'
          $package_name = 'iptables-persistent'
        }
      }
    }
    'Gentoo': {
      $service_name = ['iptables','ip6tables']
      $service_name_v6 = undef
      $package_name = 'net-firewall/iptables'
    }
    default: {
      $service_name_v6 = undef
      case $::operatingsystem {
        'Archlinux': {
          $service_name = ['iptables','ip6tables']
          $package_name = undef
        }
        default: {
          $service_name = 'iptables'
          $package_name = undef
        }
      }
    }
  }
}
