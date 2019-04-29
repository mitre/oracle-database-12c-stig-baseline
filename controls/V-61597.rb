control 'V-61597' do
  title "Owners of privileged accounts must use non-privileged accounts for
  non-administrative activities."
  desc "Use of privileged accounts for non-administrative purposes puts data
  at risk of unintended or unauthorized loss, modification, or exposure. In
  particular, DBA accounts, if used for non-administration application
  development or application maintenance, can lead to excessive privileges where
  privileges are inherited by object owners. It may also lead to loss or
  compromise of application data where the elevated privileges bypass controls
  designed in and provided by applications."
  impact 0.5
  tag "gtitle": 'SRG-APP-000063-DB-000018'
  tag "gid": 'V-61597'
  tag "rid": 'SV-76087r1_rule'
  tag "stig_id": 'O121-C2-004210'
  tag "fix_id": 'F-67513r1_fix'
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
  tag "check": "Review procedures and practices.  If there is not a policy
  requiring owners of privileged accounts to use non-privileged accounts for
  non-administrative activities, this is a finding.  If there is evidence that
  owners of privileged accounts do not adhere to this policy, this is a finding."
  tag "fix": "Require that DBAs and other privileged users use non-privileged
  accounts for non-administrative activities."
  describe 'A manual review is required to ensure owners of privileged accounts use non-privileged accounts for
    non-administrative activities' do
    skip 'A manual review is required to ensure owners of privileged accounts use non-privileged accounts for
    non-administrative activities'
  end
end
