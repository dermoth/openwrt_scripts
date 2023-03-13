# OpenWRT Scripts

(Formerly known as QoS)

## QoS Script

This is a QoS Script using the Hierarchical fair-service curve scheduler
(HFSC). It uses link-share to split bandwidth fairly between two networks (ex
you and your roommate). Then for each share, the traffic is divided in three
classes: Low-Latency, Bulk and Normal (everything else).

FAIR WARNING: I wrote this qos script with the least reliance possible on
iptables to learn the u32 classifier. The caveat is that it's much more
complex and flexible than it should, most notably it cannot to my knowledge
handle IPv6's variable header lengths. It should be rewritten to use iptables
MARK's to do proper classification (as it does to differentiate between source
LANs before traffic is masqueraded behind the router's external IP address).

1. See the script header for more info and configuration details. The traffic
   shaping schema at the top of the script can be rendered with ditaa.

2. Documentation links for the HFSC scheduler

   http://linux-ip.net/articles/hfsc.en/

   http://linuxreviews.org/man/tc-hfsc/

3. Documentation links for the u32 classifier

   http://lartc.org/howto/lartc.qdisc.filters.html

   http://lartc.org/howto/lartc.adv-filter.html

   http://ace-host.stuart.id.au/russell/files/tc/doc/cls_u32.txt

4. Open issues

   a. IPV6: getting tcp flow from multi-part headers? Seems like offset doesn't
	work even for fixed-size headers... (see ####-commended lines)

   b. Do we need RED/GRED?

## Curfew Script

Uses Firewall Traffic Rules and Cron to implement time-based Curfew. You can
also pass the rule name prefix through an environment variable, making it easy
to make different set of rules. A common prefix can also be used to "rule them
all".

See the script header for more details.

