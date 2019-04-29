control 'V-61741' do
  title "The DBMS, when utilizing PKI-based authentication, must validate
  certificates by constructing a certification path with status information to an
  accepted trust anchor."
  desc "A trust anchor is an authoritative entity represented via a public key
  and associated data. It is used in the context of public key infrastructures,
  X.509 digital certificates, and DNSSEC.

      When there is a chain of trust, usually the top entity to be trusted
  becomes the trust anchor; it can be for example a Certification Authority (CA).
  A certification path starts with the Subject certificate and proceeds through a
  number of intermediate certificates up to a trusted root certificate, typically
  issued by a trusted CA.

      Path validation is necessary for a relying party to make an informed trust
  decision when presented with any certificate not already explicitly trusted.

      Status information for certification paths includes certificate revocation
  lists or online certificate status protocol responses.

      Database Management Systems that do not validate certificates to a trust
  anchor are in danger of accepting certificates that are invalid and/or
  counterfeit. This could allow unauthorized access to the database.

      Transport Layer Security (TLS) is the successor protocol to Secure Sockets
  Layer (SSL). Although the Oracle configuration parameters have names including
  'SSL', such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000175-DB-000067'
  tag "gid": 'V-61741'
  tag "rid": 'SV-76231r3_rule'
  tag "stig_id": 'O121-C2-015300'
  tag "fix_id": 'F-67657r1_fix'
  tag "cci": ['CCI-000185']
  tag "nist": ['IA-5 (2) (a)', 'Rev_4']
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
  tag "check": "If PKI is not enabled in the Oracle Database, this is not a
  finding.

  If all accounts are authenticated by the OS or an enterprise-level
  authentication/access mechanism and not by Oracle, this is not a finding.

  Review DBMS configuration to verify the certificates being accepted by the DBMS
  have a valid certification path with status information to an accepted trust
  anchor.

  If certification paths are not being validated back to a trust anchor, this is
  a finding.

  - - - - -
  The database supports PKI-based authentication by using digital certificates
  over TLS in addition to the native encryption and data integrity capabilities
  of these protocols.

  Oracle provides a complete PKI that is based on RSA Security, Inc., Public-Key
  Cryptography Standards, and which interoperates with Oracle servers and
  clients. The database uses a wallet that is a container that is used to store
  authentication and signing credentials, including private keys, certificates,
  and trusted certificates needed by TLS. In an Oracle environment, every entity
  that communicates over TLS must have a wallet containing an X.509 version 3
  certificate, private key, and list of trusted certificates.

  If the $ORACLE_HOME/network/admin/sqlnet.ora contains the following entries,
  TLS is installed.

  WALLET_LOCATION = (SOURCE= (METHOD = FILE) (METHOD_DATA = DIRECTORY=/wallet)

  SSL_CIPHER_SUITES=(SSL_cipher_suiteExample)
  SSL_VERSION = 1.2 or 1.1
  SSL_CLIENT_AUTHENTICATION=TRUE

  (Note: This assumes that a single sqlnet.ora file, in the default location, is
  in use. Please see the supplemental file \"Non-default sqlnet.ora
  configurations.pdf\" for how to find multiple and/or differently located
  sqlnet.ora files.)

  Note: \"SSL_VERSION = 1.2 or 1.1\" is the actual value, not a suggestion to use
  one or the other."
  tag "fix": "Configure the DBMS to validate certificates by constructing a
  certification path with status information to an accepted trust anchor.

  Configure the database to support Transport Layer Security (TLS) protocols and
  the Oracle Wallet to store authentication and signing credentials, including
  private keys."

  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should include 'WALLET_LOCATION = (SOURCE= (METHOD = FILE) (METHOD_DATA = DIRECTORY=/wallet)' }
  end

  describe file "#{oracle_home}/network/admin/sqlnet.ora" do
    its('content') { should match /SSL_CIPHER_SUITES=\(\w*\)/ }
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
    its('content') { should include 'SSL_CLIENT_AUTHENTICATION=TRUE)' }
  end
end
