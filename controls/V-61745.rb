control 'V-61745' do
  title "Processes (services, applications, etc.) that connect to the DBMS
  independently of individual users, must use valid, current DoD-issued PKI
  certificates for authentication to the  DBMS."
  desc "Just as individual users must be authenticated, and just as they must
  use PKI-based authentication, so must any processes that connect to the DBMS.

      The DoD standard for authentication of a process or device communicating
  with another process or device is the presentation of a valid, current,
  DoD-issued Public Key Infrastructure (PKI) certificate that has previously been
  verified as Trusted by an administrator of the other process or device.

      This applies both to processes that run on the same server as the DBMS and
  to processes running on other computers.

      The Oracle-supplied accounts, SYS, SYSBACKUP, SYSDG, and SYSKM, are
  exceptions.  These cannot currently use certificate-based authentication.  For
  this reason among others, use of these accounts should be restricted to where
  it is truly needed.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000177-DB-000069'
  tag "gid": 'V-61745'
  tag "rid": 'SV-76235r2_rule'
  tag "stig_id": 'O121-C2-015501'
  tag "fix_id": 'F-67661r1_fix'
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
  tag "check": "Review configuration to confirm that accounts used by processes
  to connect to the DBMS are authenticated using valid, current DoD-issued PKI
  certificates.

  If any such account (other than SYS, SYSBACKUP, SYSDG, and SYSKM) is not
  certificate-based, this is a finding."
  tag "fix": 'For each such account, use DoD certificate-based authentication.'
  describe 'A manual review is required to ensure processes (services, applications, etc.) that connect to the DBMS
    independently of individual users, must use valid, current DoD-issued PKI
    certificates for authentication to the  DBMS' do
    skip 'A manual review is required to ensure processes (services, applications, etc.) that connect to the DBMS
    independently of individual users, must use valid, current DoD-issued PKI
    certificates for authentication to the  DBMS'
  end
end
