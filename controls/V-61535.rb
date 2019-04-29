control 'V-61535' do
  title 'Network client connections must be restricted to supported versions.'
  desc  "Unsupported Oracle network client installations may introduce
  vulnerabilities to the database. Restriction to use of supported versions helps
  to protect the database and helps to enforce newer, more robust security
  controls."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61535'
  tag "rid": 'SV-76025r2_rule'
  tag "stig_id": 'O121-BP-026600'
  tag "fix_id": 'F-67451r1_fix'
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
  tag "check": "Note: The SQLNET.ALLOWED_LOGON_VERSION parameter is deprecated
  in Oracle Database 12c. This parameter has been replaced with two new Oracle
  Net Services parameters:

  SQLNET.ALLOWED_LOGON_VERSION_SERVER
  SQLNET.ALLOWED_LOGON_VERSION_CLIENT

  View the SQLNET.ORA file in the ORACLE_HOME/network/admin directory or the
  directory specified in the TNS_ADMIN environment variable.  (Please see the
  supplemental file \"Non-default sqlnet.ora configurations.pdf\" for how to find
  multiple and/or differently located sqlnet.ora files.)

  Locate the following entries:

  SQLNET.ALLOWED_LOGON_VERSION_SERVER = 11
  SQLNET.ALLOWED_LOGON_VERSION_CLIENT=11

  If the parameters do not exist, this is a finding.

  If the parameters are not set to a value of 11 or higher, this is a finding.

  Note: Attempting to connect with a client version lower than specified in these
  parameters may result in a misleading error:
  ORA-01017: invalid username/password: logon denied"
  tag "fix": "Edit the SQLNET.ORA file to add or edit the entries:

  SQLNET.ALLOWED_LOGON_VERSION_SERVER = 11
  SQLNET.ALLOWED_LOGON_VERSION_CLIENT=11

  Set the value to 11 or higher.
  Valid values for SQLNET.ALLOWED_LOGON_VERSION_SERVER are:  8,9,10,11,12 and 12a

  Valid values for SQLNET.ALLOWED_LOGON_VERSION_CLIENT are:   8,10,11,12 and 12a

  For more information on sqlnet.ora parameters refer to the following document:
  \"Database Net Services Reference\"
  http://docs.oracle.com/database/121/NETRF/sqlnet.htm#NETRF006"
  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe.one do
    describe file "#{oracle_home}/network/admin/sqlnet.ora" do
      its('content') { should include 'sqlnet.allowed_logon_version_server=11' }
      its('content') { should include 'sqlnet.allowed_logon_version_client=11' }
    end

    describe file "#{oracle_home}/network/admin/sqlnet.ora" do
      its('content') { should include 'sqlnet.allowed_logon_version_server=12' }
      its('content') { should include 'sqlnet.allowed_logon_version_client=12' }
    end

    describe file "#{oracle_home}/network/admin/sqlnet.ora" do
      its('content') { should include 'sqlnet.allowed_logon_version_server=12a' }
      its('content') { should include 'sqlnet.allowed_logon_version_client=12a' }
    end
  end
end
