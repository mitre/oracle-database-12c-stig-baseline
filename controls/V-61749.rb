control 'V-61749' do
  title "The DBMS must employ cryptographic mechanisms to protect the integrity
  and confidentiality of nonlocal maintenance and diagnostic communications."
  desc "Non-local maintenance and diagnostic activities are those activities
  conducted by individuals communicating through a network, either an external
  network (e.g., the Internet) or an internal network.

      The act of managing systems and applications includes the ability to access
  sensitive application information, such as system configuration details,
  diagnostic information, user information, and potentially sensitive application
  data.

      When applications provide a remote management capability inherent to the
  application, the application needs to ensure the communication channels used to
  remotely access the system are adequately protected.  If the communication
  channel is not adequately protected authentication information, application
  data, and configuration information could be compromised.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000184-DB-000119'
  tag "gid": 'V-61749'
  tag "rid": 'SV-76239r1_rule'
  tag "stig_id": 'O121-C2-016000'
  tag "fix_id": 'F-67665r1_fix'
  tag "cci": ['CCI-002890', 'CCI-003123']
  tag "nist": ['MA-4 (6)', 'Rev_4']
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
  tag "check": "Review DBMS configuration to determine if cryptographic
  mechanisms are being utilized to protect the integrity and confidentiality of
  nonlocal maintenance and diagnostic communications.

  If not, this is a finding."
  tag "fix": "Configure DBMS to utilize cryptographic mechanisms to protect the
  integrity and confidentiality of nonlocal maintenance and diagnostic
  communications."
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
    its('content') { should include 'SSL_CLIENT_AUTHENTICATION = TRUE)' }
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
