control 'V-61715' do
  title "The DBMS must use organization-defined replay-resistant authentication
  mechanisms for network access to non-privileged accounts."
  desc "An authentication process resists replay attacks if it is impractical
  to achieve a successful authentication by recording and replaying a previous
  authentication message.

      Techniques used to address this include protocols using nonces (e.g.,
  numbers generated for a specific one-time use) or challenges (e.g., TLS,
  WS_Security), and time synchronous or challenge-response one-time
  authenticators.

      Replay attacks, if successfully used against a database account, could
  result in access to database data.  A successful replay attack against a
  non-privileged database account could result in a compromise of data stored on
  the database.

      Oracle Database enables you to encrypt data that is sent over a network.
  There is no distinction between privileged and non-privileged accounts.

      Encryption of network data provides data privacy so that unauthorized
  parties are not able to view plaintext data as it passes over the network.
  Oracle Database also provides protection against two forms of active attacks.

      Data modification attack:  An unauthorized party intercepting data in
  transit, altering it, and retransmitting it is a data modification attack. For
  example, intercepting a $100 bank deposit, changing the amount to $10,000, and
  retransmitting the higher amount is a data modification attack.

      Replay attack:  Repetitively retransmitting an entire set of valid data is
  a replay attack, such as intercepting a $100 bank withdrawal and retransmitting
  it ten times, thereby receiving $1,000.

      AES and Triple-DES operate in outer Cipher Block Chaining (CBC) mode.

      The DES algorithm uses a 56-bit key length.

      SHA-1 is in the process of being removed from service within the DoD and
  it's use is to be limited during the transition to SHA-2.  Use of SHA-1 for
  digital signature generation is prohibited.  Allowable uses during the
  transition include CHECKSUM usage and verification of legacy certificate
  signatures.  SHA-1 is considered a temporary solution during legacy application
  transitionary periods and should not be engineered into new applications. SHA-2
  is the path forward for DoD.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000157-DB-000112'
  tag "gid": 'V-61715'
  tag "rid": 'SV-76205r4_rule'
  tag "stig_id": 'O121-C2-013700'
  tag "fix_id": 'F-67631r1_fix'
  tag "cci": ['CCI-001942']
  tag "nist": ['IA-2 (9)', 'Rev_4']
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
  tag "check": "Review DBMS settings to determine whether organization-defined
  replay-resistant authentication mechanisms for network access to non-privileged
  accounts exist.

  If these mechanisms do not exist, this is a finding.

  To check that network encryption is enabled and using site-specified encryption
  procedures, look in SQLNET.ORA, located at
  $ORACLE_HOME/network/admin/sqlnet.ora. (Note: This assumes that a single
  sqlnet.ora file, in the default location, is in use. Please see the
  supplemental file \"Non-default sqlnet.ora configurations.pdf\" for how to find
  multiple and/or differently located sqlnet.ora files.) If encryption is set,
  entries like the following will be present:

  SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER= (SHA384)
  SQLNET.ENCRYPTION_TYPES_SERVER=(AES256)
  SQLNET.CRYPTO_CHECKSUM_SERVER = required

  SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT= (SHA384)
  SQLNET.ENCRYPTION_TYPES_CLIENT= (AES256)
  SQLNET.CRYPTO_CHECKSUM_CLIENT = requested

  (The values assigned to the parameters may be different, the combination of
  parameters may be different, and not all of the example parameters will
  necessarily exist in the file.)"
  tag "fix": "Configure DBMS, OS and/or enterprise-level authentication/access
  mechanism to require organization-defined replay-resistant authentication
  mechanisms for network access to non-privileged accounts.

  If appropriate, apply Oracle Data Network Encryption to protect against replay
  mechanisms."
  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER= (SHA384)' }
  end

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SQLNET.ENCRYPTION_TYPES_SERVER=(AES256)' }
  end

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_SERVER = required' }
  end

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT= (SHA384)' }
  end

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SQLNET.ENCRYPTION_TYPES_CLIENT= (AES256)' }
  end

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'SQLNET.CRYPTO_CHECKSUM_CLIENT = requested' }
  end
end
