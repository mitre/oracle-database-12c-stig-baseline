control 'V-61523' do
  title "Remote DBMS administration must be documented and authorized or
  disabled."
  desc "Remote administration may expose configuration and sensitive data to
  unauthorized viewing during transit across the network or allow unauthorized
  administrative access to the DBMS to remote users.

      For the purposes of this STIG, \"Remote\" means \"outside the DoDIN.\"
  However, use of an approved and properly configured VPN counts as inside the
  DoDIN.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61523'
  tag "rid": 'SV-76013r3_rule'
  tag "stig_id": 'O121-BP-026000'
  tag "fix_id": 'F-67439r4_fix'
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
  tag "check": "Review the System Security Plan for authorization, assignments
  and usage procedures for remote DBMS administration.

  If remote administration of the DBMS is not documented or poorly documented,
  this is a finding.

  If remote administration of the DBMS is not authorized and not disabled, this
  is a finding.

  If remote administration is to be performed from outside the DoDIN, but is not
  done via an approved and properly configured VPN, this is a finding."
  tag "fix": "Disable remote administration of the DBMS where not required.

  Where remote administration of the DBMS is required, develop, document and
  implement policy and procedures on its use.

  Assign remote administration privileges to ISSO-authorized personnel only.

  Document assignments in the System Security Plan.

  Where remote administration is to be performed from outside the DoDIN,
  configure an approved VPN client for this purpose."
  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
  end
  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end
