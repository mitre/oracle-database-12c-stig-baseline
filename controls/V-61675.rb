control 'V-61675' do
  title "The DBMS must enforce requirements for remote connections to the
  information system."
  desc "Applications that provide remote access to information systems must be
  able to enforce remote access policy requirements or work in conjunction with
  enterprise tools designed to enforce policy requirements. Examples of policy
  requirements include, but are not limited to, authorizing remote access to the
  information system, limiting access based on authentication credentials, and
  monitoring for unauthorized access.

      If databases allowing remote connections do not enforce requirements for
  remote access, an attacker may gain access to the database and may, through the
  database, gain access to other components of the information system.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000140-DB-000033'
  tag "gid": 'V-61675'
  tag "rid": 'SV-76165r1_rule'
  tag "stig_id": 'O121-C2-011400'
  tag "fix_id": 'F-67589r1_fix'
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
  tag "check": "Review organization's access control policies and procedures
  addressing remote access to the information system.

  If remote connections are not allowed by the organization, this is NA. (Note
  that \"remote\" means \"from outside the DoD Information Network (DoDIN)\" and
  that connections via approved Virtual Private Networks (VPNs) are considered to
  be inside the DoDIN.)

  Review the DBMS, OS, and/or enterprise account management settings to verify
  access controls and auditing settings exist and they enforce the requirements
  for remote access defined by the organization.

  If access controls and auditing do not exist or do not fully enforce the
  requirements defined in the organization's policies and procedures, this is a
  finding."
  tag "fix": "Configure DBMS settings to ensure access control and auditing
  requirements for remote connections are enforced by the DBMS."
  describe sshd_config do
    its('PermitRootLogin') { should eq 'no' }
  end
  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end
