control 'V-61457' do
  title 'Audit trail data must be reviewed daily or more frequently.'
  desc  "Review of audit trail data provides a means for detection of
  unauthorized access or attempted access. Frequent and regularly scheduled
  reviews ensure that such access is discovered in a timely manner."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61457'
  tag "rid": 'SV-75947r1_rule'
  tag "stig_id": 'O121-BP-023500'
  tag "fix_id": 'F-67373r2_fix'
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
  tag "check": "If the database being reviewed is not a production database,
  this check is not a finding.

  Review policy and procedures documented or noted in the System Security plan as
  well as evidence of implementation for daily audit trail monitoring.

  If policy and procedures are not documented or evidence of implementation is
  not available, this is a finding."
  tag "fix": "Develop, document and implement policy and procedures to monitor
  audit trail data daily."
  describe 'A manual review is required to ensure audit trail data is reviewed daily or more frequently' do
    skip 'A manual review is required to ensure audit trail data is reviewed daily or more frequently'
  end
end
