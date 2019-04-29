control 'V-61647' do
  title "The system must alert designated organizational officials in the event
  of an audit processing failure."
  desc  "It is critical for the appropriate personnel to be aware if a system
  is at risk of failing to process audit logs as required. Audit processing
  failures include: software/hardware errors, failures in the audit capturing
  mechanisms, and audit storage capacity being reached or exceeded.

      A failure of database auditing will result in either the database
  continuing to function without auditing or in a complete halt to database
  operations. When audit processing fails, appropriate personnel must be alerted
  immediately to avoid further downtime or unaudited transactions.

      If Oracle Enterprise Manager is in use, the capability to issue such an
  alert is built in and configurable via the console so an alert can be sent to a
  designated administrator.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000108-DB-000048'
  tag "gid": 'V-61647'
  tag "rid": 'SV-76137r2_rule'
  tag "stig_id": 'O121-C2-008500'
  tag "fix_id": 'F-67561r3_fix'
  tag "cci": ['CCI-000139']
  tag "nist": ['AU-5 a', 'Rev_4']
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
  tag "check": "Review OS or third-party logging application settings to
  determine whether an alert will be sent to the designated organizational
  personnel when auditing fails for any reason.

  If no alert will be sent, this is a finding."
  tag "fix": "Modify OS or third-party logging application settings to alert
  designated organizational personnel when auditing fails for any reason.

  If Oracle Enterprise Manager is in use, the capability to issue such an alert
  is built in and configurable via the console so an alert can be sent to a
  designated administrator."
  describe 'A manual review is required to ensure the system alerts designated organizational officials in the event
    of an audit processing failure' do
    skip 'A manual review is required to ensure the system alerts designated organizational officials in the event
    of an audit processing failure'
  end
end
