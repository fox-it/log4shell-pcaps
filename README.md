# Log4Shell PCAPS and Network Coverage

Since the publication of the [Log4Shell exploit](https://www.lunasec.io/docs/blog/log4j-zero-day/) there have been a lot of developments surrounding the [Log4j CVE](https://logging.apache.org/log4j/2.x/security.html), leading to several new versions of the package to fix the workarounds that people found for the mitigations. During this time, there were also many people focusing their efforts on finding evasive methods to bypass mitigations put in place that block exploitation by monitoring for the exploitation string.

Because of the variety of the evasive methods, and the different protocols that can be used to exploit the vulnerability, we have created pcaps and an overview to assist security engineers in their endeavours to check their current detection coverage.

## Setup

[RIFT](https://research.nccgroup.com/2021/12/12/log4shell-reconnaissance-and-post-exploitation-network-detection) has used an environment to test different scenarios with the purpose of automatically creating pcaps and testing network coverage for the Remote Code Execution (RCE) vectors of Log4Shell using `LDAP` and `RMI`. 

We tested different vectors that attackers could use in real-world scenarios, focusing on the HTTP protocol as this has been observed being used in the wild. Please keep in mind that HTTP is by no means the only protocol attackers can use to trigger the vulnerability in applications using a vulnerable version of Log4j. Any string that is logged by a vulnerable Log4j is subject to exploitation. We have also seen different evasion techniques, so these have also been tested for coverage.

We want to emphasize that we already observed attackers using encoded variants of the available protocols (HTTP Basic Authorization) and that there are plentiful other encoding methods that might still be logged decoded by the application using a vulnerable Log4j package.

We have used the following tools for testing the exploitation:

 * [JNDIExploit](https://github.com/feihong-cs/JNDIExploit) for LDAP <sup>github repo down</sup>
 * [JNDI-Exploit-Kit](https://github.com/pimps/JNDI-Exploit-Kit) for LDAP and RMI

For web applications that is vulnerable to log4shell we have used:

 * [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app)
 * [docker-vuln-log4j-webapp](https://github.com/fox-it/log4shell-pcaps/tree/main/docker-vuln-log4j-webapp)


## Log4Shell PCAPs and Coverage Tracking

The tables displayed below give an overview of the different evasion methods and their respective coverage. The PCAP filenames contain the `ev` string to mark the evasion ID.


| EV           | Payload |
|-----------------|---------|
| 1 | `${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://` <br> `${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://` |
| 2 | `${${lower:jndi}:${lower:ldap}://` <br> `${${::-j}ndi:rmi://`|
| 3 | `${${lower:${lower:jndi}}:${lower:ldap}://` <br> `${${lower:jndi}:${lower:rmi}://`|
| 4 | `${${lower:j}${lower:n}${lower:d}i:${lower:ldap}://` <br> `${${lower:${lower:jndi}}:${lower:rmi}://` |
| 5 | `${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}d${lower:a}p://` <br> `${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}://` |
| 6 | `${j${env:DOESNOTEXIST:-}ndi:ldap://` <br> `${j${env:DOESNOTEXIST:-}ndi:rmi://` |
| 7 | `${${:  :  : : :::   :: :: :  :::-j}ndi:ldap://` <br> `${${:  :  : : :::   :: :: :  :::-j}ndi:rmi://` |
| 8 | `${${::::::::::::::-j}ndi:ldap://` <br> `${${::::::::::::::-j}ndi:rmi://` |


### Log4Shell LDAP Exploitation PCAPS

We have configured the RCE payload in our tests to execute the following ping command `ping -c 10 1.1.1.1`, these can be observed in the PCAPs.

PS: You can hover of the signature ids (SIDS) to see the rule name.


#### Log4Shell in URI encoded parameters

PCAP examples using URL encoded forms of the Log4Shell exploit strings in the URI parameters, most http clients will URL encode these strings and thus need to be normalised for detection. Suricata has support for this when using the `http` keywords.

<details>
  <summary>LDAP pcaps</summary>
<table>
  <thead>
    <th>EV</th>
    <th>PCAP</th>
    <th>SIDS</th>
  </thead>
  <tbody>
    <tr>
      <td>0</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-uri-params-ev0.pcap">ldap-uri-params-ev0.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>1</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-uri-params-ev1.pcap">ldap-uri-params-ev1.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>2</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-uri-params-ev2.pcap">ldap-uri-params-ev2.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI (strict)">21003735</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>3</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-uri-params-ev3.pcap">ldap-uri-params-ev3.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI (strict)">21003735</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>4</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-uri-params-ev4.pcap">ldap-uri-params-ev4.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI (strict)">21003735</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>5</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-uri-params-ev5.pcap">ldap-uri-params-ev5.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI (strict)">21003735</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>6</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-uri-params-ev6.pcap">ldap-uri-params-ev6.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI (strict)">21003735</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>7</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-uri-params-ev7.pcap">ldap-uri-params-ev7.pcap</a><br><sup>failed exploitation</sup></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>8</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-uri-params-ev8.pcap">ldap-uri-params-ev8.pcap</a><br><sup>failed exploitation</sup></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
  </tbody>
</table>
</details>

<details>
  <summary>RMI pcaps</summary>
<table>
  <thead>
    <th>EV</th>
    <th>PCAP</th>
    <th>SIDS</th>
  </thead>
  <tbody>
    <tr>
      <td>0</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-uri-params-ev0.pcap">rmi-uri-params-ev0.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>1</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-uri-params-ev1.pcap">rmi-uri-params-ev1.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>2</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-uri-params-ev2.pcap">rmi-uri-params-ev2.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI (strict)">21003735</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>3</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-uri-params-ev3.pcap">rmi-uri-params-ev3.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI (strict)">21003735</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>4</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-uri-params-ev4.pcap">rmi-uri-params-ev4.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI (strict)">21003735</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>5</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-uri-params-ev5.pcap">rmi-uri-params-ev5.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI (strict)">21003735</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>6</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-uri-params-ev6.pcap">rmi-uri-params-ev6.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI (strict)">21003735</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>7</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-uri-params-ev7.pcap">rmi-uri-params-ev7.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>8</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-uri-params-ev8.pcap">rmi-uri-params-ev8.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
  </tbody>
</table>
</details>

#### Log4Shell in HTTP Headers

PCAP examples using different HTTP headers as a general means to illustrate this vector of exploitation. Note that the header used does not matter, as long as it is being logged by an application using a vulnerable Log4j version.

<details>
  <summary>LDAP pcaps (User-Agent)</summary>
<table>
  <thead>
    <th>EV</th>
    <th>PCAP</th>
    <th>SIDS</th>
  </thead>
  <tbody>
    <tr>
      <td>0</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-user-agent-ev0.pcap">ldap-user-agent-ev0.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>1</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-user-agent-ev1.pcap">ldap-user-agent-ev1.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>2</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-user-agent-ev2.pcap">ldap-user-agent-ev2.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>3</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-user-agent-ev3.pcap">ldap-user-agent-ev3.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>4</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-user-agent-ev4.pcap">ldap-user-agent-ev4.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>5</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-user-agent-ev5.pcap">ldap-user-agent-ev5.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>6</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-user-agent-ev6.pcap">ldap-user-agent-ev6.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>7</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-user-agent-ev7.pcap">ldap-user-agent-ev7.pcap</a><br><sup>failed exploitation</sup></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in URI">21003733</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
    <tr>
      <td>8</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-user-agent-ev8.pcap">ldap-user-agent-ev8.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Java class inbound">21003742</a>, <a href="#signatures" title="FOX-SRT - Suspicious - .class Retrieval from External using Java">21003750</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible JNDI LDAP Exploitation Observed">21003751</a></td>
    </tr>
  </tbody>
</table>
</details>

<details>
  <summary>RMI pcaps (User-Agent)</summary>

<table>
  <thead>
    <th>EV</th>
    <th>PCAP</th>
    <th>SIDS</th>
  </thead>
  <tbody>
    <tr>
      <td>0</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-user-agent-ev0.pcap">rmi-user-agent-ev0.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>1</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-user-agent-ev1.pcap">rmi-user-agent-ev1.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>2</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-user-agent-ev2.pcap">rmi-user-agent-ev2.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>3</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-user-agent-ev3.pcap">rmi-user-agent-ev3.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>4</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-user-agent-ev4.pcap">rmi-user-agent-ev4.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>5</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-user-agent-ev5.pcap">rmi-user-agent-ev5.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>6</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-user-agent-ev6.pcap">rmi-user-agent-ev6.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>7</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-user-agent-ev7.pcap">rmi-user-agent-ev7.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>8</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-user-agent-ev8.pcap">rmi-user-agent-ev8.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
  </tbody>
</table>
</details>

<details>
  <summary>RMI pcaps (X-Api-Version)</summary>

<table>
  <thead>
    <th>EV</th>
    <th>PCAP</th>
    <th>SIDS</th>
  </thead>
  <tbody>
    <tr>
      <td>0</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-x-api-version-ev0.pcap">rmi-x-api-version-ev0.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>1</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-x-api-version-ev1.pcap">rmi-x-api-version-ev1.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>2</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-x-api-version-ev2.pcap">rmi-x-api-version-ev2.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>3</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-x-api-version-ev3.pcap">rmi-x-api-version-ev3.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>4</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-x-api-version-ev4.pcap">rmi-x-api-version-ev4.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>5</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-x-api-version-ev5.pcap">rmi-x-api-version-ev5.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>6</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-x-api-version-ev6.pcap">rmi-x-api-version-ev6.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>7</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-x-api-version-ev7.pcap">rmi-x-api-version-ev7.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>8</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-x-api-version-ev8.pcap">rmi-x-api-version-ev8.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>9</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-x-api-version-ev9.pcap">rmi-x-api-version-ev9.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a></td>
    </tr>
  </tbody>
</table>
</details>
    

#### Log4Shell in Basic Authorization (base64 encoded)

PCAP examples using the Log4Shell exploit strings in the `Basic Authorization` header. Note that this header is Base64 encoded as `username:password` which poses a tricky way for network detection. We use the `base64_decode` keyword in Suricata rules for this.

<details>
  <summary>LDAP pcaps</summary>

<table>
  <thead>
    <th>EV</th>
    <th>PCAP</th>
    <th>SIDS</th>
  </thead>
  <tbody>
    <tr>
      <td>0</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-basic-auth-ev0.pcap">ldap-basic-auth-ev0.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Exploit - Java class inbound after CVE-2021-44228 exploit attempt (xbit)">21003741</a></td>
    </tr>
    <tr>
      <td>1</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-basic-auth-ev1.pcap">ldap-basic-auth-ev1.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Exploit - Java class inbound after CVE-2021-44228 exploit attempt (xbit)">21003741</a></td>
    </tr>
    <tr>
      <td>2</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-basic-auth-ev2.pcap">ldap-basic-auth-ev2.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header (strict)">21003756</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Exploit - Java class inbound after CVE-2021-44228 exploit attempt (xbit)">21003741</a></td>
    </tr>
    <tr>
      <td>3</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-basic-auth-ev3.pcap">ldap-basic-auth-ev3.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header (strict)">21003756</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Exploit - Java class inbound after CVE-2021-44228 exploit attempt (xbit)">21003741</a></td>
    </tr>
    <tr>
      <td>4</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-basic-auth-ev4.pcap">ldap-basic-auth-ev4.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header (strict)">21003756</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Exploit - Java class inbound after CVE-2021-44228 exploit attempt (xbit)">21003741</a></td>
    </tr>
    <tr>
      <td>5</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-basic-auth-ev5.pcap">ldap-basic-auth-ev5.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header (strict)">21003756</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Exploit - Java class inbound after CVE-2021-44228 exploit attempt (xbit)">21003741</a></td>
    </tr>
    <tr>
      <td>6</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-basic-auth-ev6.pcap">ldap-basic-auth-ev6.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header (strict)">21003756</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Exploit - Java class inbound after CVE-2021-44228 exploit attempt (xbit)">21003741</a></td>
    </tr>
    <tr>
      <td>7</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-basic-auth-ev7.pcap">ldap-basic-auth-ev7.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Exploit - Java class inbound after CVE-2021-44228 exploit attempt (xbit)">21003741</a></td>
    </tr>
    <tr>
      <td>8</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/ldap-basic-auth-ev8.pcap">ldap-basic-auth-ev8.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JNDI LDAP Bind to External Observed (CVE-2021-44228)">21003738</a>, <a href="#signatures" title="FOX-SRT - Exploit - Java class inbound after CVE-2021-44228 exploit attempt (xbit)">21003741</a></td>
    </tr>
  </tbody>
</table>
</details>

<details>
  <summary>RMI pcaps</summary>

<table>
  <thead>
    <th>EV</th>
    <th>PCAP</th>
    <th>SIDS</th>
  </thead>
  <tbody>
    <tr>
      <td>0</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-basic-auth-ev0.pcap">rmi-basic-auth-ev0.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>1</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-basic-auth-ev1.pcap">rmi-basic-auth-ev1.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>2</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-basic-auth-ev2.pcap">rmi-basic-auth-ev2.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header (strict)">21003756</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>3</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-basic-auth-ev3.pcap">rmi-basic-auth-ev3.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header (strict)">21003756</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>4</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-basic-auth-ev4.pcap">rmi-basic-auth-ev4.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header (strict)">21003756</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>5</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-basic-auth-ev5.pcap">rmi-basic-auth-ev5.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header (strict)">21003756</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>6</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-basic-auth-ev6.pcap">rmi-basic-auth-ev6.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header (strict)">21003756</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>7</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-basic-auth-ev7.pcap">rmi-basic-auth-ev7.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
    <tr>
      <td>8</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-rmi-pcaps/rmi-basic-auth-ev8.pcap">rmi-basic-auth-ev8.pcap</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in Basic Auth Header">21003755</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - Exploit - Possible Rogue JRMI Request to External Observed (CVE-2021-44228)">21003739</a></td>
    </tr>
  </tbody>
</table>
</details>

#### Log4Shell via LDAPS (TLS)

PCAP examples displaying the Log4Shell exploitation, using the TLS encrypted `LDAP` callback with the supported `ldaps` protocol in Log4j. The client random keys can be found in the `.pcapng` files to decrypt the traffic to look at the plaintext contents.

In our research we found that the LDAPS server needs to have a valid TLS certificate as the exploited Java application verifies TLS connections by default. So for an attacker to ensure that the payloads go over TLS sucessfully the attacker needs to host a server with a valid TLS certificate. Because the traffic goes over TLS it is difficult to distinguish between normal Web TLS traffic if the attacker chooses port 443 as the `LDAPS` port.

<table>
  <thead>
    <th>EV</th>
    <th>PCAP</th>
    <th>SIDS</th>
  </thead>
  <tbody>
    <tr>
      <td>None</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/log4shell-ldaps-port-443-dsb.pcapng">log4shell-ldaps-port-443-dsb.pcapng</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible internal LOG4J exploit attempt in HTTP Header (strict)">21003748</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4J RCE Request Observed (CVE-2021-44228)">21003728</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228)">21003730</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4J RCE Successful Response Observed (CVE-2021-44228)">21003727</a></td>
    </tr>
    <tr>
      <td>None</td>
      <td><a href="https://github.com/fox-it/log4shell-pcaps/raw/main/log4shell-ldap-pcaps/log4shell-ldaps-port-1399-dsb.pcapng">log4shell-ldaps-port-1399-dsb.pcapng</a></td>
      <td><a href="#signatures" title="FOX-SRT - EXPLOIT - Possible internal LOG4J exploit attempt in HTTP Header (strict)">21003748</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4J RCE Request Observed (CVE-2021-44228)">21003728</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Defense-Evasive Apache Log4J RCE Request Observed (CVE-2021-44228)">21003730</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header">21003732</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4j Exploit Attempt in HTTP Header (strict)">21003734</a>, <a href="#signatures" title="FOX-SRT - Suspicious - Possible outgoing connection after Log4j Exploit Attempt">21003740</a>, <a href="#signatures" title="FOX-SRT - EXPLOIT - Possible Apache Log4J RCE Successful Response Observed (CVE-2021-44228)">21003727</a></td>
    </tr>
  </tbody>
</table>


While detection of Log4Shell in TLS traffic (to port 443) is challenging, we have thought about the following detection opportunities:

  * TLS packet sizes:
      * The first TLS encrypted Application data *request* is tiny
         * LDAP bindRequest: 85 bytes encrypted, 14 bytes decrypted
      * The first TLS encrypted Application data *response* is also tiny
         * LDAP bindResponse success: 85 bytes encrypted, 14 bytes decrypted
  * JA3(s) hashes

We hope the infosec community has some bright ideas on improving detection here.


# Signatures

Our Log4Shell Suricata signatures can be found here: [log4shell-suricata.rules](suricata/log4shell-suricata.rules)

We have found that our signatures for outgoing `LDAP` and `RMI` packets are the best indicators (sids 21003738 and 21003739) of detecting a successful Log4Shell detonation. This also covers the situation where the malicious JNDI string is not always detected, for example due to TLS, but the IDS still monitors outgoing traffic.

Furthermore, the exploit chain itself might not always succeed, for example, due to Java versions or hardening of the system and or network. However, when these signatures trigger, a vulnerable Log4j version performed the callback and should be further investigated to determine which application caused it.
