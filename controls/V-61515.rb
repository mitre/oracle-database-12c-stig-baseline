control 'V-61515' do
  title 'Network access to the DBMS must be restricted to authorized personnel.'
  desc  "Restricting remote access to specific, trusted systems helps prevent
  access by unauthorized and potentially malicious users."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61515'
  tag "rid": 'SV-76005r2_rule'
  tag "stig_id": 'O121-BP-025600'
  tag "fix_id": 'F-67431r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
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
  tag "check": "IP address restriction may be defined for the database
  listener, by use of the Oracle Connection Manager or by an external network
  device.

  Identify the method used to enforce address restriction (interview or System
  Security Plan review).

  If enforced by the database listener, then review the SQLNET.ORA file located
  in the ORACLE_HOME/network/admin directory (note: this assumes that a single
  sqlnet.ora file, in the default location, is in use; please see the
  supplemental file \"Non-default sqlnet.ora configurations.pdf\" for how to find
  multiple and/or differently located sqlnet.ora files) or the directory
  indicated by the TNS_ADMIN environment variable or registry setting.

  If the following entries do not exist, then restriction by IP address is not
  configured and is a finding.

  tcp.validnode_checking=YES
  tcp.invited_nodes=(IP1, IP2, IP3)

  If enforced by an Oracle Connection Manager, then review the CMAN.ORA file for
  the Connection Manager (located in the TNS_ADMIN or ORACLE_HOME/network/admin
  directory for the connection manager).

  If a RULE entry allows all addresses (\"/32\") or does not match the address
  range specified in the System Security Plan, this is a finding.

  (rule=(src=[IP]/27)(dst=[IP])(srv=*)(act=accept))

  Note: an IP address with a \"/\" indicates acceptance by subnet mask where the
  number after the \"/\" is the left most number of bits in the address that must
  match for the rule to apply.

  If this rule is database-specific, then determine if the SERVICE_NAMES
  parameter is set:

  From SQL*PLUS:

  select value from v$parameter where name = 'service_names';

  If SERVICE_NAMES is set in the initialization file for the database instance,
  use (srv=[service name]), else, use (srv=*) if not set or rule applies to all
  databases on the DBMS server.

  If network access restriction is performed by an external device, validate ACLs
  are in place to prohibit unauthorized access to the DBMS.  To do this, find the
  IP address of the database server (destination address) and source address
  (authorized IPs) in the System Security Plan.  Confirm only authorized IPs from
  the System Security Plan are allowed access to the DBMS."
  tag "fix": "Configure the database listener to restrict access by IP address
  or set up an external device to restrict network access to the DBMS."

  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'tcp.validnode_checking=YES' }
    its('content') { should match /tcp.invited_nodes=(\W*)/ }
  end
end
