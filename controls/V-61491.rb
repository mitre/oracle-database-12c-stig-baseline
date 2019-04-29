control 'V-61491' do
  title "The DBMS host platform and other dependent applications must be
  configured in compliance with applicable STIG requirements."
  desc "The security of the data stored in the DBMS is also vulnerable to
  attacks against the host platform, calling applications, and other application
  or optional components."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61491'
  tag "rid": 'SV-75981r1_rule'
  tag "stig_id": 'O121-BP-024300'
  tag "fix_id": 'F-67407r1_fix'
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
  tag "check": "If the DBMS host being reviewed is not a production DBMS host,
  this check is not a finding.

  Review evidence of security hardening and auditing of the DBMS host platform
  with the ISSO.

  If the DBMS host platform has not been hardened and received a security audit,
  this is a finding.

  Review evidence of security hardening and auditing for all application(s) that
  store data in the database and all other separately configured components that
  access the database including web servers, application servers, report servers,
  etc.

  If any have not been hardened and received a security audit, this is a finding.

  Review evidence of security hardening and auditing for all application(s)
  installed on the local DBMS host where security hardening and auditing guidance
  exists.

  If any have not been hardened and received a security audit, this is a finding."
  tag "fix": "Configure all related application components and the DBMS host
  platform in accordance with the applicable DoD STIG.

  Regularly audit the security configuration of related applications and the host
  platform to confirm continued compliance with security requirements."
  describe 'A manual review is required to ensure the DBMS host platform and other dependent applications are
    configured in compliance with applicable STIG requirements' do
    skip 'A manual review is required to ensure the DBMS host platform and other dependent applications are
    configured in compliance with applicable STIG requirements'
  end
end
