# Table to use.
type Firewall::Table = Enum[
  'filter',
  'mangle',
  'nat',
  'raw',
  'rawpost',
]
