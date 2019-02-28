control "V-61709" do
  title "The DBMS must use multifactor authentication for local access to
  non-privileged accounts."
  desc  "Multifactor authentication is defined as using two or more factors to
  achieve authentication.

      Factors include:
      (i) Something a user knows (e.g., password/PIN);
      (ii) Something a user has (e.g., cryptographic identification device,
  token); or
      (iii) Something a user is (e.g., biometric).

      A non-privileged account is defined as an information system account with
  authorizations of a regular or non-privileged user.

      Local Access is defined as access to an organizational information system
  by a user (or process acting on behalf of a user) communicating through a
  direct connection without the use of a network.

      The lack of multifactor authentication makes it much easier for an attacker
  to gain unauthorized access to a system.

      Transport Layer Security (TLS) is the successor protocol to Secure Sockets
  Layer (SSL). Although the Oracle configuration parameters have names including
  'SSL', such as SSL_VERSION and SSL_CIPHER_SUITES, they refer to TLS.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000152-DB-000107"
  tag "gid": "V-61709"
  tag "rid": "SV-76199r2_rule"
  tag "stig_id": "O121-C2-013200"
  tag "fix_id": "F-67625r1_fix"
  tag "cci": ["CCI-000768"]
  tag "nist": ['IA-2 (4)', 'Rev_4']
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
  tag "check": "Review DBMS settings, OS settings, and/or enterprise-level
  authentication/access mechanism settings to determine whether users logging on
  to non-privileged accounts locally are required to use multifactor
  authentication.

  If users logging on to privileged accounts locally are not required to use
  multifactor authentication, this is a finding.

  Use authentication to prove the identities of users who are attempting to log
  on to the database. Authenticating user identity is imperative in distributed
  environments, without which there can be little confidence in network security.
  Passwords are the most common means of authentication. Oracle Database enables
  strong authentication with Oracle authentication adapters that support various
  third-party authentication services, including TLS with digital certificates.

  If the $ORACLE_HOME/network/admin/sqlnet.ora contains entries similar to the
  following, TLS is enabled.
  (Note: This assumes that a single sqlnet.ora file, in the default location, is
  in use. Please see the supplemental file \"Non-default sqlnet.ora
  configurations.pdf\" for how to find multiple and/or differently located
  sqlnet.ora files.)

  SQLNET.AUTHENTICATION_SERVICES= (BEQ, TCPS)
  SSL_VERSION = 1.2 or 1.1
  SSL_CLIENT_AUTHENTICATION = TRUE
  WALLET_LOCATION =
    (SOURCE =
      (METHOD = FILE)
      (METHOD_DATA =
        (DIRECTORY = /u01/app/oracle/product/12.1.0/dbhome_1/owm/wallets)
      )
    )
  SSL_CIPHER_SUITES= (SSL_RSA_WITH_AES_256_CBC_SHA384)
  ADR_BASE = /u01/app/oracle

  Note:  \"SSL_VERSION = 1.2 or 1.1\" is the actual value, not a suggestion to
  use one or the other."
  tag "fix": "Configure DBMS, OS and/or enterprise-level authentication/access
  mechanism to require multifactor authentication for local users logging on to
  non-privileged accounts.

  If appropriate, enable support for Transport Layer Security (TLS) protocols and
  multifactor authentication through the use of Smart Cards (CAC/PIV)."

  oracle_home = command('echo $ORACLE_HOME').stdout.strip

  describe file ("#{oracle_home}/network/admin/sqlnet.ora") do
    its('content') { should include 'SQLNET.AUTHENTICATION_SERVICES= (BEQ, TCPS)' }
  end

  describe.one do 
    describe file ("#{oracle_home}/network/admin/sqlnet.ora") do
      its('content') { should include 'SSL_VERSION = 1.2' }
    end
    describe file ("#{oracle_home}/network/admin/sqlnet.ora") do
      its('content') { should include 'SSL_VERSION = 1.1' }
    end
  end

  describe file ("#{oracle_home}/network/admin/sqlnet.ora") do
    its('content') { should include 'SSL_CLIENT_AUTHENTICATION = TRUE)' }
  end

  describe file ("#{oracle_home}/network/admin/sqlnet.ora") do
    its('content') { should include 'WALLET_LOCATION = (SOURCE = (METHOD = FILE) (METHOD_DATA = (DIRECTORY = /u01/app/oracle/product/12.1.0/dbhome_1/owm/wallets)))' }
  end

  describe file ("#{oracle_home}/network/admin/sqlnet.ora") do
    its('content') { should include 'SSL_CIPHER_SUITES= (SSL_RSA_WITH_AES_256_CBC_SHA384)' }
  end

  describe file ("#{oracle_home}/network/admin/sqlnet.ora") do
    its('content') { should include 'ADR_BASE = /u01/app/oracle' }
  end
end

