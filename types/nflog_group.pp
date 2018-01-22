# An integer from 0 to 65535, or the string equivalent.
type Firewall::Nflog_group = Variant[
  Integer[0,65535],
  Pattern[/\A(0|[1-9]\d{0,3}|[1-5]\d{4}|6([1-4]\d{3}|5([1-4]\d{2}|5([0-2]\d|3[0-5]))))\z/]
]
