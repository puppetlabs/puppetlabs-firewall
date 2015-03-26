# This class creates custom firewall rules using hieradata
class firewall::custom_firewall {

  Firewall {
    before  => Class['firewall::post'],
    require => Class['firewall::pre'],
  }

  $rules  = hiera_hash('firewall::custom_firewall',{})

  if !empty($rules) {
    create_resources('firewall', $rules)
  }
}
