control "V-61489" do
  title "Use of the DBMS installation account must be logged."
  desc  "The DBMS installation account may be used by any authorized user to
perform DBMS installation or maintenance. Without logging, accountability for
actions attributed to the account is lost."
  impact 0.5
  tag "gtitle": "SRG-APP-000516-DB-999900"
  tag "gid": "V-61489"
  tag "rid": "SV-75979r1_rule"
  tag "stig_id": "O121-BP-024200"
  tag "fix_id": "F-67405r1_fix"
  tag "cci": ["CCI-000366"]
  tag "nist": ["Rev_4"]
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
  tag "check": "Review documented and implemented procedures for monitoring the
use of the DBMS software installation account in the System Security Plan.

If use of this account is not monitored or procedures for monitoring its use do
not exist or are incomplete, this is a finding.

Note: On Windows systems, The Oracle DBMS software is installed using an
account with administrator privileges. Ownership should be reassigned to a
dedicated OS account used to operate the DBMS software. If monitoring does not
include all accounts with administrator privileges on the DBMS host, this is a
finding."
  tag "fix": "Develop, document and implement a logging procedure for use of
the DBMS software installation account that provides accountability to
individuals for any actions taken by the account.

Host system audit logs should be included in the DBMS account usage log along
with an indication of the person who accessed the account and an explanation
for the access.

Ensure all accounts with administrator privileges are monitored for DBMS host
on Windows OS platforms."
end

