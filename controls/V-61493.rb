control 'V-61493' do
  title "Remote administrative access to the database must be monitored by the
  ISSO or ISSM."
  desc "Remote administrative access to systems provides a path for access to
  and exploit of DBA privileges. Where the risk has been accepted to allow remote
  administrative access, it is imperative to instate increased monitoring of this
  access to detect any abuse or compromise."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61493'
  tag "rid": 'SV-75983r1_rule'
  tag "stig_id": 'O121-BP-024400'
  tag "fix_id": 'F-67409r1_fix'
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
  tag "check": "If remote administrative access to the database is prohibited
  and is disabled, this check is not a finding.

  Review policy, procedure and evidence of implementation for monitoring of
  remote administrative access to the database.

  If monitoring procedures for remote administrative access are not documented or
  implemented, this is a finding."
  tag "fix": "Develop, document and implement policy and procedures to monitor
  remote administrative access to the DBMS.

  The automated generation of a log report with automatic dissemination to the
  ISSO/ISSM may be used.

  Require and store an acknowledgement of receipt and confirmation of review for
  the log report."
  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
  end
  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end
