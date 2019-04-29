control 'V-61503' do
  title "Sensitive data stored in the database must be identified in the System
  Security Plan and AIS Functional Architecture documentation."
  desc "A DBMS that does not have the correct confidentiality level identified
  or any confidentiality level assigned is not being secured at a level
  appropriate to the risk it poses."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61503'
  tag "rid": 'SV-75993r1_rule'
  tag "stig_id": 'O121-BP-024900'
  tag "fix_id": 'F-67419r1_fix'
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
  tag "check": "If no sensitive or classified data is stored in the database,
  listed in the System Security Plan and listed in the AIS Functional
  Architecture documentation, this check is not a finding.

  Review AIS Functional Architecture documentation for the DBMS and note any
  sensitive data that is identified.

  Review database table column data or descriptions that indicate sensitive data.

  For example, a data column labeled \"SSN\" could indicate social security
  numbers are stored in the column.

  Question the ISSO or DBA where any questions arise.

  General categories of sensitive data requiring identification include any
  personal data (health, financial, social security number and date of birth),
  proprietary or financially sensitive business data or data that might be
  classified.

  If any data is considered sensitive and is not documented in the AISFA, this is
  a finding."
  tag "fix": "Include identification of any sensitive data in the AIS
  Functional Architecture and the System Security Plan.

  Include data that appear to be sensitive with a discussion as to why it is not
  marked as such."
  describe 'A manual review is required to ensure sensitive data stored in the database is identified in the System
    Security Plan and AIS Functional Architecture documentation' do
    skip 'A manual review is required to ensure sensitive data stored in the database is identified in the System
    Security Plan and AIS Functional Architecture documentation'
  end
end
