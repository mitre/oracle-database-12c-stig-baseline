control 'V-61409' do
  title 'Audit trail data must be retained for at least one year.'
  desc  "Without preservation, a complete discovery of an attack or suspicious
  activity may not be determined.  DBMS audit data also contributes to the
  complete investigation of unauthorized activity and needs to be included in
  audit retention plans and procedures."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61409'
  tag "rid": 'SV-75899r1_rule'
  tag "stig_id": 'O121-BP-021100'
  tag "fix_id": 'F-67325r1_fix'
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
  tag "check": "Review and verify the implementation of an audit trail
  retention policy.

  Verify that audit data is maintained for a minimum of one year.

  If audit data is not maintained for a minimum of one year, this is a finding."
  tag "fix": "Develop, document and implement an audit retention policy and
  procedures.

  It is recommended that the most recent thirty days of audit logs remain
  available online.

  After thirty days, the audit logs may be maintained off-line.

  Online maintenance provides for a more timely capability and inclination to
  investigate suspicious activity."
  describe 'A manual review is required to ensure audit trail data is retained for at least one year' do
    skip 'A manual review is required to ensure audit trail data is retained for at least one year'
  end
end
