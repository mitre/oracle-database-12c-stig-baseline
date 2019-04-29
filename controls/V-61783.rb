control 'V-61783' do
  title "The DBMS must protect against or limit the effects of
  organization-defined types of Denial of Service (DoS) attacks."
  desc "A variety of technologies exist to limit, or in some cases, eliminate
  the effects of DoS attacks. For example, boundary protection devices can filter
  certain types of packets to protect devices on an organization's internal
  network from being directly affected by DoS attacks.

      Employing increased capacity and bandwidth combined with service redundancy
  may reduce the susceptibility to some DoS attacks.

      Some of the ways databases can limit their exposure to DoS attacks are
  through limiting the number of connections that can be opened by a single user
  and database clustering.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000245-DB-000132'
  tag "gid": 'V-61783'
  tag "rid": 'SV-76273r1_rule'
  tag "stig_id": 'O121-C2-019100'
  tag "fix_id": 'F-67699r1_fix'
  tag "cci": ['CCI-002385']
  tag "nist": ['SC-5', 'Rev_4']
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
  tag "check": "Review DBMS settings to verify the DBMS implements measures to
  limit the effects of the organization-defined types of Denial of Service (DoS)
  attacks.

  If measures have not been implemented, this is a finding.

  Check the $ORACLE_HOME/network/admin/listener.ora to see if a Rate Limit has
  been established.  A rate limit is used to prevent denial of service (DOS)
  attacks on a database or to control a logon storm such as may be caused by an
  application server reboot.

  - - - - -
  Example of a listener configuration with rate limiting in effect:

  CONNECTION_RATE_LISTENER=10

  LISTENER=
    (ADDRESS_LIST=
      (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1521)(RATE_LIMIT=yes))
      (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1522)(RATE_LIMIT=yes))
      (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1526))
    )
  LISTENER=
    (ADDRESS_LIST=
      (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1521)(RATE_LIMIT=8))
      (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1522)(RATE_LIMIT=12))
      (ADDRESS=(PROTOCOL=tcp)(HOST=)(PORT=1526))
    )"
  tag "fix": "Implement measures to limit the effects of organization-defined
  types of Denial of Service attacks.

  Modify the $ORACLE_HOME/network/admin/listener.ora to establish a Rate Limit."

  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/listener.ora" do
    its('content') { should include 'RATE_LIMIT=' }
    its('content') { should match /CONNECTION_RATE_LISTENER=\d*/ }
  end
end
