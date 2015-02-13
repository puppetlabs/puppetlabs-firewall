class firewall::params {
  case $::osfamily {
    'RedHat': {
      case $::operatingsystem {
        'Amazon': {
          $service_name = 'iptables'
          $package_name = undef
        }
        'Archlinux': {
          $service_name = ['iptables','ip6tables']
          $package_name = undef
        }
        'Fedora': {
          if versioncmp($::operatingsystemrelease, '15') >= 0 {
            $package_name = 'iptables-services'
          } else {
            $package_name = undef
          }
          $service_name = 'iptables'
        }
        default: {
          if versioncmp($::operatingsystemrelease, '7.0') >= 0 {
            $package_name = 'iptables-services'
          } else {
            $package_name = 'iptables-ipv6'
          }
          $service_name = 'iptables'
        }
      }
    }
    'Debian': {
      case $::operatingsystem {
        'Debian': {
          if versioncmp($::operatingsystemrelease, '8.0') >= 0 {
            $service_name = 'netfilter-persistent'
            $package_name = 'netfilter-persistent'
          } else {
            $service_name = 'iptables-persistent'
            $package_name = 'iptables-persistent'
          }

        }
        'Ubuntu': {
          if versioncmp($::operatingsystemrelease, '14.10') >= 0 {
            $service_name = 'netfilter-persistent'
            $package_name = 'netfilter-persistent'
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
    default: {
      $package_name = undef
      $service_name = 'iptables'
    }
  }
}
