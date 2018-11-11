# The canonical name of the rule must start with a number.
type Firewall::Name = Pattern[/\A\d+[[:graph:][:space:]]+\z/]
