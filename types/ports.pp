# A port, array of ports, or port range in the form of Port1-Port2.
# Due to pattern-match limitations this does not exclude repeated
# values such as [1,1,1,1,1] or nonsense such as '100-99'.
type Firewall::Ports = Variant[
  Array[Firewall::Port,1,15]
  Firewall::Port,
  Pattern[/\A([1-9][0-9]{0,3}|[1-5][0-9]{4}|6([1-4][0-9]{3}|5([1-4][0-9]{2}|5([0-2][0-9]|3[0-5]))))-([1-9][0-9]{0,3}|[1-5][0-9]{4}|6([1-4][0-9]{3}|5([1-4][0-9]{2}|5([0-2][0-9]|3[0-5]))))\z/],
]
