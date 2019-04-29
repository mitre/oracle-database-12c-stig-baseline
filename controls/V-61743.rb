control 'V-61743' do
  title "The DBMS must map the authenticated identity to the user account using
  PKI-based authentication."
  desc "The cornerstone of the PKI is the private key used to encrypt or
  digitally sign information. The key by itself is a cryptographic value that
  does not contain specific user information.

      When including the DBMS in the Private Key Infrastructure, the
  authenticated user must map directly to a user account in the DBMS. If the user
  account is not directly tied to the authenticated identity, there is no way to
  know which, if any, database user account has been authorized.

      Transport Layer Security (TLS) is the successor protocol to Secure Sockets
  Layer (SSL). Although the Oracle configuration parameters have names including
  'SSL', such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000177-DB-000069'
  tag "gid": 'V-61743'
  tag "rid": 'SV-76233r2_rule'
  tag "stig_id": 'O121-C2-015500'
  tag "fix_id": 'F-67659r1_fix'
  tag "cci": ['CCI-000187']
  tag "nist": ['IA-5 (2) (c)', 'Rev_4']
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
  tag "check": "Review DBMS configuration to verify DBMS user accounts are
  being mapped directly to authenticated identity information being passed via
  the PKI.

  If user accounts are not being mapped to authenticated identity information
  being passed via the PKI, this is a finding.

  - - - - -
  The database supports PKI-based authentication by using digital certificates
  over TLS in addition to the native encryption and data integrity capabilities
  of these protocols.

  Oracle provides a complete PKI that is based on RSA Security, Inc., Public-Key
  Cryptography Standards, and which interoperates with Oracle servers and
  clients.  The database uses a wallet that is a container that is used to store
  authentication and signing credentials, including private keys, certificates,
  and trusted certificates needed by TLS. In an Oracle environment, every entity
  that communicates over TLS must have a wallet containing an X.509 version 3
  certificate, private key, and list of trusted certificates.  Security
  administrators use Oracle Wallet Manager to manage security credentials on the
  server.

  If the $ORACLE_HOME/network/admin/sqlnet.ora contains the following entries,
  TLS is installed. (Note: This assumes that a single sqlnet.ora file, in the
  default location, is in use. Please see the supplemental file \"Non-default
  sqlnet.ora configurations.pdf\" for how to find multiple and/or differently
  located sqlnet.ora files.)

  WALLET_LOCATION = (SOURCE=
                            (METHOD = FILE)
                            (METHOD_DATA =
                             DIRECTORY=/wallet)

  SSL_CIPHER_SUITES=(SSL_cipher_suiteExample)
  SSL_VERSION = 1.2 or 1.1
  SSL_CLIENT_AUTHENTICATION=FALSE/TRUE

  Note:  \"SSL_VERSION = 1.2 or 1.1\" is the actual value, not a suggestion to
  use one or the other."
  tag "fix": "Configure the DBMS to map the authenticated identity directly to
  the DBMS user account."

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

  describe.one do
    describe file "#{oracle_home}/network/admin/sqlnet.ora" do
      its('content') { should include 'SSL_CLIENT_AUTHENTICATION=TRUE)' }
    end
    describe file "#{oracle_home}/network/admin/sqlnet.ora" do
      its('content') { should include 'SSL_CLIENT_AUTHENTICATION=FALSE)' }
    end
  end
end
