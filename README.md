# fastsnmp
SNMP poller oriented to poll bunch of hosts in short time. Package include poller and SNMP coder/encoder library.

Example:
```python
from fastsnmp import snmp_poller

hosts = ("127.0.0.1",)
# oids in group must be with same indexes
oid_group = {"1.3.6.1.2.1.2.2.1.2": "ifDescr",
             "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
             }

community = "public"
snmp_data = snmp_poller.poller(hosts, (oid_group.keys(),), community)
for d in snmp_data:
    print ("host=%s oid=%s.%s value=%s" % (d[0], oid_group[d[1]], d[2], d[3]))
```
Output:
```
host=127.0.0.1 oid=ifInOctets.1 value=243203744
host=127.0.0.1 oid=ifDescr.1 value=lo
host=127.0.0.1 oid=ifInOctets.2 value=1397428486
host=127.0.0.1 oid=ifDescr.2 value=eth0
```
Another python SNMP libraries:

* [PySNMP](http://pysnmp.sourceforge.net/) - very good SNMP library
* [libsnmp](https://pypi.python.org/pypi/libsnmp) - SNMP coder/decoder (abandoned project)
* [Bindings to Net-SNMP](http://net-snmp.sourceforge.net/wiki/index.php/Python_Bindings)
