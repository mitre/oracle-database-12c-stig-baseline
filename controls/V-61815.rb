control 'V-61815' do
  title "The DBMS must restrict the ability of users to launch Denial of
  Service (DoS) attacks against other information systems or networks."
  desc "When it comes to DoS attacks, most of the attention is paid to
  ensuring that systems and applications are not victims of these attacks.

      While it is true that those accountable for systems want to ensure they are
  not affected by a DoS attack, they also need to ensure their systems and
  applications are not used to launch such an attack against others. To that
  extent, a variety of technologies exist to limit, or in some cases, eliminate
  the effects of DoS attacks.

      For example, boundary protection devices can filter certain types of
  packets to protect devices from being directly affected by  DoS attacks.
  Limiting system resources that are allocated to any user to a bare minimum may
  also reduce the ability of users to launch some DoS attacks.

      Applications and application developers must take the steps needed to
  ensure users cannot use these applications to launch DoS attacks against other
  systems and networks. An example would be designing applications to include
  mechanisms that throttle network traffic so users are not able to generate
  unlimited network traffic via the application.

      The methods employed to counter this risk will be dependent upon the
  potential application layer methods that can be used to exploit it.

      This calls for inspection of application source code, which will require
  collaboration with the application developers. It is recognized that in many
  cases, the database administrator (DBA) is organizationally separate from the
  application developers and may have limited, if any, access to source code.
  Nevertheless, protections of this type are so important to the secure operation
  of databases that they must not be ignored. At a minimum, the DBA must attempt
  to obtain assurances from the development organization that this issue has been
  addressed and must document what has been discovered.
    "
  impact 0.3
  tag "gtitle": 'SRG-APP-000246-DB-000133'
  tag "gid": 'V-61815'
  tag "rid": 'SV-76305r4_rule'
  tag "stig_id": 'O121-C3-019200'
  tag "fix_id": 'F-67731r10_fix'
  tag "cci": ['CCI-001094']
  tag "nist": ['SC-5 (1)', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Review DBMS settings and custom database code to determine
  whether the DBMS or database application code could be used to launch DoS
  attacks.

  If the DBMS or custom database code would facilitate DoS-style attacks against
  other information systems, this is a finding.

  The Listener is the key for a denial of service attack.  Check to insure the
  appropriate steps to secure the Oracle Listener are in place at the site.
  (Refer to the Fix for more detail on implementing these protections.)"
  tag "fix": "Configure DBMS settings to restrict functionality that could be
  used to initiate DoS attacks.

  Securing the Network Connection:
  Protecting the network and its traffic from inappropriate access or
  modification is the essence of network security. You should consider all paths
  the data travels, and assess the threats on each path and node. Then, take
  steps to lessen or eliminate those threats and the consequences of a security
  breach. In addition, monitor and audit to detect either increased threat levels
  or penetration attempts.

  The following practices improve network security:

  1. Disable the Default Listener.
  All listeners have a unique name instead of the name LISTENER and have startup
  protection.

  LISTENER=(DESCRIPTION =(ADDRESS = (PROTOCOL = TCP)(HOST=)(PORT = 0)))

  This configuration prevents the default listener from starting.

  2. Prevent online administration by requiring the administrator to have the
  write privilege on the listener.ora file on the server.
  a. Add or alter this line in the listener.ora file:

  ADMIN_RESTRICTIONS_LISTENER=ON

  b. Use RELOAD to reload the configuration.

  3. Set Protection against crafted network packets on database level.

  SEC_PROTOCOL_ERROR_TRACE_ACTION specifies the action that the database should
  take when bad packets are received from a possibly malicious client.

  SEC_PROTOCOL_ERROR_TRACE_ACTION = { NONE | TRACE | LOG | ALERT } (TRACE is the
  default)

  NONE: The database server ignores the bad packets and does not generate any
  trace files or log messages. (Not recommended)

  TRACE: A detailed trace file is generated when bad packets are received, which
  can be used to debug any problems in client/server communication.

  LOG: A minimal log message is printed in the alert logfile and in the server
  trace file. A minimal amount of disk space is used.

  ALERT: An alert message is sent to a DBA or monitoring console.

  SEC_PROTOCOL_ERROR_FURTHER_ACTION specifies the further execution of a server
  process when receiving bad packets from a possibly malicious client.

  SEC_PROTOCOL_ERROR_FURTHER_ACTION = { CONTINUE | (DELAY,integer) |
  (DROP,integer) } (DROP,3 is the default)

  CONTINUE: The server process continues execution. The database server may be
  subject to a Denial of Service (DoS) if bad packets continue to be sent by a
  malicious client. (Not recommended)

  (DELAY, integer) :The client experiences a delay of integer seconds before the
  server process accepts the next request from the same client connection.
  Malicious clients are prevented from excessive consumption of server resources
  while legitimate clients experience degradation in performance but can continue
  to function.

  (DROP, integer) : The server forcefully terminates the client connection after
  integer bad packets. The server protects itself at the expense of the client
  (for example, a client transaction may be lost). The client may reconnect and
  attempt the same operation.

  SEC_MAX_FAILED_LOGIN_ATTEMPTS specifies the number of authentication attempts
  that can be made by a client on a connection to the server process. After the
  specified number of failure attempts, the connection will be automatically
  dropped by the server process.

  SEC_MAX_FAILED_LOGIN_ATTEMPTS = n (3 is the default) Values range from 1 to
  unlimited. (A value of 1 to 3 is recommended)

  For more information about the parameters in listener.ora, see
  https://docs.oracle.com/database/121/NETRF/listener.htm#NETRF008

  4. When a host computer has multiple IP addresses associated with multiple
  network interface controller (NIC) cards, configure the listener to the
  specific IP address.

  You can restrict the listener to listen on a specific IP address. Oracle
  recommends that you specify the specific IP addresses on these types of
  computers, rather than allowing the listener to listen on all IP addresses.
  Restricting the listener to specific IP addresses helps to prevent an intruder
  from stealing a TCP end point from under the listener process.

  5. Restrict the privileges of the listener, so that it cannot read or write
  files in the database or the Oracle server address space.

  The default configuration for external procedures does not require a network
  listener to work with Oracle Database and the extproc agent. The extproc agent
  is spawned directly by Oracle Database and eliminates the risks that the
  extproc agent might be spawned by Oracle Listener unexpectedly. This default
  configuration is recommended for maximum security. For more information about
  securing external procedures see
  https://docs.oracle.com/database/121/DBSEG/app_devs.htm#DBSEG656
  However, the extproc agent can be configured to be spawned by a listener. In
  that case (not recommended) the listener should have restricted privileges.

  6. Use a firewall, IAW DoD network policy and guidance.

  Appropriately placed and configured firewalls can prevent outside access to
  your databases.

  7. Prevent unauthorized administration of the Oracle listener.

  Local administration of the listener is secure by default through the local
  operating system. Therefore configuring a password is neither required nor
  recommended for secure local administration. However, a password can be
  configured for the listener to provide security for administrative operations,
  such as starting or stopping the listener, viewing a list of supported
  services, or saving changes to the Listener Control configuration.

  By default, Oracle Net Listener permits only local administration for security
  reasons. As a policy, the listener can be administered only by the user who
  started it. This is enforced through local operating system authentication. For
  example, if user1 starts the listener, then only user1 can administer it. Any
  other user trying to administer the listener gets an error. The super user is
  the only exception.

  Oracle recommends that you perform listener administration in the default mode
  (secure by means of local operating system authentication), and access the
  system remotely using a remote logon. Oracle Enterprise Manager Cloud Control
  can also be used for remote administration.

  8. Encrypt network traffic.  (Mandatory for sensitive data and optional for
  non-sensitive, as covered in other STIG requirements.)

  Where applicable, use Oracle network data encryption to encrypt network traffic
  among clients, databases, and application servers.

  9. Set Connect Rate to organization defined limit. (Also required by
  O121-C2-019100/SRG-APP-000245-DB-000132)

  The connection rate limiter feature in Oracle Net Listener enables a database
  administrator to limit the number of new connections handled by the listener.
  When this feature is enabled, Oracle Net Listener imposes a user-specified
  maximum limit on the number of new connections handled by the listener every
  second.

  CONNECTION_RATE_LISTENER=10
  LISTENER=
  (ADDRESS_LIST=
  (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1521)(RATE_LIMIT=yes))
  (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1522)(RATE_LIMIT=yes))
  (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1526))
  )

  10. Setup Valid Node Checking.
  (See also O121-BP-025600.)

  Valid node checking is a security feature that protects DBMS instances from
  malevolent or errant Oracle Net connections over TCP/IP, without the need for a
  firewall or IP address filtering at the operating system-level. The feature is
  controlled by the three parameters; tcp.validnode_checking, tcp.invited_nodes,
  and tcp.excluded_nodes.

  Modify the sqlnet.ora file manually
  TCP.VALIDNODE_CHECKING=yes
  (Note: This assumes that a single sqlnet.ora file, in the default location, is
  in use. Please see the supplemental file \"Non-default sqlnet.ora
  configurations.pdf\" for how to find multiple and/or differently located
  sqlnet.ora files.)

  If this parameter is set to yes, then incoming connections are allowed only if
  they originate from a node that conforms to the list specified by
  TCP.INVITED_NODES or TCP.EXCLUDED_NODES parameters.

  The TCP.INVITED_NODES and TCP.EXCLUDED_NODES parameters are valid only when the
  TCP.VALIDNODE_CHECKING parameter is set to yes (no is the default).

  The TCP.INVITED_NODES and TCP.EXCLUDED_NODES parameters are valid only when the
  TCP.VALIDNODE_CHECKING parameter is set to yes.

  Modify the listener.ora file manually

  TCP.EXCLUDED_NODES Syntax:
  TCP.EXCLUDED_NODES=(hostname | ip_address, hostname | ip_address, ...)

  Example:
  TCP.EXCLUDED_NODES=(finance.us.example.com, mktg.us.example.com, 192.0.2.25,
  172.30.*, 2001:DB8:200C:417A/32)

  TCP.INVITED_NODES Syntax:
  TCP.INVITED_NODES=(hostname | ip_address, hostname | ip_address, ...)

  Example:
  TCP.INVITED_NODES=(sales.us.example.com, hr.us.example.com, 192.0.*,
  2001:DB8:200C:433B/32)

  Usage Notes:

  Use TCP.INVITED_NODES to specify which clients are allowed access to the
  database. This list takes precedence over the TCP.EXCLUDED_NODES parameter if
  both lists are present. These parameters can use wildcards for IPv4 addresses
  and CIDR notation for IPv4 and IPv6 addresses.

  11. Apply Listener Security Patches.
  (See also O121-C1-011100/SRG-APP-000133-DB-000205.)

  Critical Patch Updates are cumulative. Therefore, the latest patch will contain
  all previous security patches for the Listener.

  12. Ensure that listener logging is turned on.

  Listener logging is on by default. If logging is not on, configure logging for
  all listeners in order to capture Listener commands and brute force password
  attacks.

  13. Monitor the listener logfile.

  The logfile may contain TNS-01169, TNS-01189, TNS-01190, or TNS-12508 errors,
  which may signify attacks or inappropriate activity. Monitor the logfile and
  generate an alert whenever these errors are encountered."
  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/listener.ora" do
    its('content') { should include 'LISTENER=(DESCRIPTION =(ADDRESS = (PROTOCOL = TCP)(HOST=)(PORT = 0)))' }
    its('content') {
      should include 'LISTENER=
    (ADDRESS_LIST=
      (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1521)(RATE_LIMIT=yes))
      (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1522)(RATE_LIMIT=yes))
      (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1526))'
    }
    its('content') { should include 'CONNECTION_RATE_LISTENER=10' }
    its('content') { should include 'SEC_MAX_FAILED_LOGIN_ATTEMPTS=3' }
    its('content') { should include 'ADMIN_RESTRICTIONS_LISTENER=ON' }
    its('content') { should include 'SEC_PROTOCOL_ERROR_TRACE_ACTION=TRACE' }
    its('content') { should include 'TCP.INVITED_NODES=' }
    its('content') { should include 'TCP.EXCLUDED_NODES=' }
  end

  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'TCP.VALIDNODE_CHECKING=yes' }
  end
end
