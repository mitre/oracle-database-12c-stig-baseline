control 'V-61447' do
  title "Connections by mid-tier web and application systems to the Oracle DBMS
  from a DMZ or external network must be encrypted.
  "
  desc "Multi-tier systems may be configured with the database and connecting
  middle-tier system located on an internal network, with the database located on
  an internal network behind a firewall and the middle-tier system located in a
  DMZ. In cases where either or both systems are located in the DMZ (or on
  networks external to DoD), network communications between the systems must be
  encrypted."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61447'
  tag "rid": 'SV-75937r2_rule'
  tag "stig_id": 'O121-BP-023000'
  tag "fix_id": 'F-67363r2_fix'
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
  tag "check": "Review the System Security Plan for remote applications that
  access and use the database.

  For each remote application or application server, determine whether
  communications between it and the DBMS are encrypted. If any are not encrypted,
  this is a finding."
  tag "fix": "Configure communications between the DBMS and remote
  applications/application servers to use DoD-approved encryption."
  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SQLNET.AUTHENTICATION_SERVICES= (BEQ, TCPS)' }
  end

  describe.one do
    describe file "#{oracle_home}/network/admin/sqlnet.ora" do
      its('content') { should include 'SSL_VERSION = 1.2' }
    end
    describe file "#{oracle_home}/network/admin/sqlnet.ora" do
      its('content') { should include 'SSL_VERSION = 1.1' }
    end
  end

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SSL_CLIENT_AUTHENTICATION = TRUE' }
  end
  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SSL_CIPHER_SUITES= (SSL_RSA_WITH_AES_256_CBC_SHA384)' }
  end

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT= (SHA384)' }
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER= (SHA384)' }
    its('content') { should include 'SQLNET.ENCRYPTION_TYPES_CLIENT= (AES256)' }
    its('content') { should include 'SQLNET.ENCRYPTION_TYPES_SERVER= (AES256)' }
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_CLIENT = requested' }
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_SERVER = required' }
  end
end
