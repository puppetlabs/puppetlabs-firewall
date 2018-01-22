# A string with a list of comma-separated flag names for the mask,
# then a space, then a comma-separated list of flags that should be set.
# The flags are: SYN ACK FIN RST URG PSH ALL NONE
# Note that you specify them in the order that iptables --list-rules would
# list them to avoid having puppet think you changed the flags.
# Example: FIN,SYN,RST,ACK SYN matches packets with the SYN bit set and the
# ACK, RST and FIN bits cleared.  Such packets are used to request TCP
# connection initiation.
type Firewall::Tcp_flags = Pattern[/\A(((((SYN(,ACK)?|ACK)(,FIN)?|FIN)(,RST)?|RST)(,URG)?|URG)(,PSH)?|PSH|ALL|NONE)[[:blank:]]+(((((SYN(,ACK)?|ACK)(,FIN)?|FIN)(,RST)?|RST)(,URG)?|URG)(,PSH)?|PSH|ALL|NONE)\z/]
