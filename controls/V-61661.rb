control "V-61661" do
  title "The system must protect audit tools from unauthorized modification."
  desc  "Protecting audit data also includes identifying and protecting the
  tools used to view and manipulate log data.

      Depending upon the log format and application, system and application log
  tools may provide the only means to manipulate and manage application and
  system log data.

      If the tools are compromised it could provide attackers with the capability
  to manipulate log data. It is, therefore, imperative that audit tools be
  controlled and protected from unauthorized modification.

      Audit tools include, but are not limited to, OS provided audit tools,
  vendor provided audit tools, and open source audit tools needed to successfully
  view and manipulate audit information system activity and records.

      If an attacker were to gain access to audit tools he could analyze audit
  logs for system weaknesses or weaknesses in the auditing itself. An attacker
  could also manipulate logs to hide evidence of malicious activity.
  "
  impact 0.5
  tag "gtitle": "SRG-APP-000122-DB-000203"
  tag "gid": "V-61661"
  tag "rid": "SV-76151r1_rule"
  tag "stig_id": "O121-C2-009700"
  tag "fix_id": "F-67575r1_fix"
  tag "cci": ["CCI-001494"]
  tag "nist": ['AU-9', 'Rev_4']
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
  tag "check": "Review access permissions to tools used to view or modify audit
  log data. These tools may include the DBMS itself or tools external to the
  database.

  If appropriate permissions and access controls are not applied to prevent
  unauthorized modification of these tools, this is a finding."
  tag "fix": "Add or modify access controls and permissions to tools used to
  view or modify audit log data. Tools must be modifiable by authorized personnel
  only."
  describe 'A manual review is required to ensure the system protects audit tools from unauthorized modification' do
    skip 'A manual review is required to ensure the system protects audit tools from unauthorized modification'
  end
end

