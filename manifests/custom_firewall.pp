# This class creates custom firewall rules using hieradata
class firewall::custom_firewall (

  $rules  = {},
  $manage = true,
) {

  validate_hash($rules)
  validate_bool($manage)

  resources { 'firewall':
    purge => true,
  }

  if $firewall_data != false {
    create_resources('firewall', $rules)
  }
}
