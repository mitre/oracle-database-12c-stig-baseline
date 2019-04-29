control 'V-61453' do
  title "Sensitive information from production database exports must be
  modified before import to a development database."
  desc "Data export from production databases may include sensitive data.
  Application developers do not have a need to know to sensitive data. Any access
  they may have to production data would be considered unauthorized access and
  subject the sensitive data to unlawful or unauthorized disclosure. See DODD
  8500.1 for a definition of Sensitive Information."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61453'
  tag "rid": 'SV-75943r2_rule'
  tag "stig_id": 'O121-BP-023300'
  tag "fix_id": 'F-67369r1_fix'
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
  tag "check": "If the database being reviewed is a production database, this
  check is not a finding.

  Review policy, procedures and restrictions for data imports of production data
  containing sensitive information into development databases.

  If data imports of production data are allowed, review procedures for
  protecting any sensitive data included in production exports.

  If sensitive data is included in the exports and no procedures are in place to
  remove or modify the data to render it not sensitive prior to import into a
  development database or policy and procedures are not in place to ensure
  authorization of development personnel to access sensitive information
  contained in production data, this is a finding."
  tag "fix": "Develop, document and implement policy, procedures and
  restrictions for production data import.

  Require any users assigned privileges that allow the export of production data
  from the database to acknowledge understanding of import policies, procedures
  and restrictions.

  Restrict permissions of development personnel requiring use or access to
  production data imported into development databases containing sensitive
  information to authorized users.

  Implement policy and procedures to modify or remove sensitive information in
  production exports prior to import into development databases."
  describe 'A manual review is required to ensure sensitive information from production database exports are
  modified before import to a development database' do
    skip 'A manual review is required to ensure sensitive information from production database exports are
    modified before import to a development database'
  end
end
