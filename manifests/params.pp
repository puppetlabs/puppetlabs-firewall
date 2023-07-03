# @summary Provides defaults for the Apt module parameters
#
# @api private
#
class firewall::params {
  $package_ensure = 'present'
  case $facts['os']['family'] {
    'RedHat': {
      case $facts['os']['name'] {
        'Amazon': {
          $service_name = 'iptables'
          $service_name_v6 = 'ip6tables'
          $package_name = undef
          $iptables_name = 'iptables'
          $sysconfig_manage = true
          $firewalld_manage = true
        }
        'Fedora': {
          $service_name = 'iptables'
          $service_name_v6 = 'ip6tables'
          if versioncmp($facts['os']['release']['full'], '34') >= 0 {
            $package_name = 'iptables-services'
            $iptables_name = 'iptables-compat'
          } else {
            $iptables_name = 'iptables'
            $package_name = undef
          }
          $sysconfig_manage = true
          $firewalld_manage = true
        }
        default: {
          if versioncmp($facts['os']['release']['full'], '9') >= 0 {
            $service_name = ['nftables','iptables']
            $service_name_v6 = 'ip6tables'
            $package_name = ['iptables-services', 'nftables', 'iptables-nft-services']
            $iptables_name = 'iptables-nft'
            $sysconfig_manage = false
            $firewalld_manage = true
          } elsif versioncmp($facts['os']['release']['full'], '8.0') >= 0 {
            $service_name = ['iptables', 'nftables']
            $service_name_v6 = 'ip6tables'
            $package_name = ['iptables-services', 'nftables']
            $iptables_name = 'iptables'
            $sysconfig_manage = false
            $firewalld_manage = true
          } elsif versioncmp($facts['os']['release']['full'], '7.0') >= 0 {
            $service_name = 'iptables'
            $service_name_v6 = 'ip6tables'
            $package_name = 'iptables-services'
            $iptables_name = 'iptables'
            $sysconfig_manage = true
            $firewalld_manage = true
          } else {
            $service_name = 'iptables'
            $service_name_v6 = 'ip6tables'
            $package_name = 'iptables-ipv6'
            $iptables_name = 'iptables'
            $sysconfig_manage = true
            $firewalld_manage = true
          }
        }
      }
    }
    'Debian': {
      $service_name_v6 = undef
      $iptables_name = 'iptables'
      case $facts['os']['name'] {
        'Debian': {
          if versioncmp($facts['os']['release']['full'], 'unstable') >= 0 {
            $service_name = 'netfilter-persistent'
            $package_name = 'netfilter-persistent'
          } elsif versioncmp($facts['os']['release']['full'], '8.0') >= 0 {
            $service_name = 'netfilter-persistent'
            $package_name = 'iptables-persistent'
          } else {
            $service_name = 'iptables-persistent'
            $package_name = 'iptables-persistent'
          }
        }
        'Ubuntu': {
          if versioncmp($facts['os']['release']['full'], '14.10') >= 0 {
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
      $iptables_name = 'iptables'
      $service_name_v6 = undef
      case $facts['os']['name'] {
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
