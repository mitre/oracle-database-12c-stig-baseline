control 'V-61499' do
  title "Plans and procedures for testing DBMS installations, upgrades and
  patches must be defined and followed prior to production implementation."
  desc "Updates and patches to existing software have the intention of
  improving the security or enhancing or adding features to the product. However,
  it is unfortunately common that updates or patches can render production
  systems inoperable or even introduce serious vulnerabilities. Some updates also
  set security configurations back to unacceptable settings that do not meet
  security requirements. For these reasons, it is a good practice to test updates
  and patches offline before introducing them in a production environment."
  impact 0.5
  tag "gtitle": 'SRG-APP-000516-DB-999900'
  tag "gid": 'V-61499'
  tag "rid": 'SV-75989r1_rule'
  tag "stig_id": 'O121-BP-024700'
  tag "fix_id": 'F-67415r1_fix'
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
  tag "check": "Review policy and procedures documented or noted in the System
  Security Plan and evidence of implementation for testing DBMS installations,
  upgrades and patches prior to production deployment.

  If policy and procedures do not exist or evidence of implementation does not
  exist, this is a finding."
  tag "fix": "Develop, document and implement procedures for testing DBMS
  installations, upgrades and patches prior to deployment on production systems."
  describe 'A manual review is required to ensure plans and procedures for testing DBMS installations, upgrades and
    patches are defined and followed prior to production implementation' do
    skip 'A manual review is required to ensure plans and procedures for testing DBMS installations, upgrades and
    patches are defined and followed prior to production implementation'
  end
end
