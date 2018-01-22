# A syslog severity name or number.
type Firewall::Log_level = Variant[
  Integer[0,7],
  Pattern[/\A([0-7]|alert|crit|debug|err(or)?|info|not(ice)?|panic|warn(ing)?)\z/],
]
