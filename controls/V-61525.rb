control 'V-61525' do
  title "DBMS symmetric keys must be protected in accordance with NSA or
  NIST-approved key management technology or processes."
  desc "Symmetric keys used for encryption protect data from unauthorized
  access. However, if not protected in accordance with acceptable standards, the
  keys themselves may be compromised and used for unauthorized data access."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61525'
  tag "rid": 'SV-76015r1_rule'
  tag "stig_id": 'O121-BP-026100'
  tag "fix_id": 'F-67441r1_fix'
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
  tag "check": "If the symmetric key management procedures and configuration
  settings for the DBMS are not specified in the System Security Plan, this is a
  finding.

  If the procedures are not followed, with evidence for audit, this is a finding.

  Note:  This check does not include a review of the key management procedures
  for validity. Specific key management requirements may be covered under
  separate checks."
  tag "fix": "Implement the following for symmetric and other encryption keys:
  -  protection from unauthorized access in transit and in storage
  -  utilization of accepted algorithms
  -  generation in accordance with required standards for the key's use
  -  expiration date
  -  continuity - key backup and recovery
  -  key change
  -  archival key storage (as necessary)

  Details for key management requirements are provided by FIPS 140-2 key
  management standards available from NIST."
  describe 'A manual review is required to ensure the DBMS symmetric keys are protected in accordance with NSA or
    NIST-approved key management technology or processes.' do
    skip 'A manual review is required to ensure the DBMS symmetric keys are protected in accordance with NSA or
    NIST-approved key management technology or processes.'
  end
end
