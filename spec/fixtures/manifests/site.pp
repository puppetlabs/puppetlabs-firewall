node 'actual.resource' {
  firewall { '102 Monitoring 22 tcp access':
    chain       => 'DOCKER',
    dport       => 22,
    destination => '172.30.0.3',
    proto       => 'tcp',
    action      => 'accept',
  }
}
