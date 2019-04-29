control 'V-61617' do
  title "Databases utilizing Discretionary Access Control (DAC) must enforce a
  policy that limits propagation of access rights."
  desc "Discretionary Access Control (DAC) is based on the premise that
  individual users are owners of objects and therefore have discretion over
  who should be authorized to access the object and in which mode (e.g., read or
  write). Ownership is usually acquired as a consequence of creating the object
  or via specified ownership assignment.

      DAC allows the owner to determine who will have access to objects they
  control. An example of DAC includes user-controlled file permissions. DAC
  models have the potential for the access controls to propagate without limit,
  resulting in unauthorized access to said objects.

      When applications provide a discretionary access control mechanism, the
  application must be able to limit the propagation of those access rights.

      The DBMS must ensure the recipient of permissions possesses only the access
  intended. The database must enforce the ability to limit rights propagation if
  that is the intent of the grantor. If the propagation of access rights is not
  limited, users with rights to objects they do not own can continue to grant
  rights to those objects to other users without limit.

      This is default behavior for Oracle.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000085-DB-000038'
  tag "gid": 'V-61617'
  tag "rid": 'SV-76107r1_rule'
  tag "stig_id": 'O121-C2-006600'
  tag "fix_id": 'F-67533r1_fix'
  tag "cci": ['CCI-002165']
  tag "nist": ['AC-3 (4)', 'Rev_4']
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
  tag "check": "Verify the DBMS has the ability to grant permissions without
  the grantee receiving the right to grant those same permissions to another user.

  Review organization policies regarding access propagation. If an access
  propagation policy limiting the propagation of rights does not exist, this is a
  finding.

  Review DBMS configuration to verify access propagation policies are enforced by
  the DBMS as configured. If the DBMS does not enforce the access propagation
  policy, this is a finding."
  tag "fix": "Create and document an access propagation policy that limits the
  propagation of rights.

  Configure the DBMS to enforce the access propagation policy.

  When a user is granted access to an object, they have access to the object.
  When a user is granted access to an object with the GRANT option, then they can
  provide permissions to others.  Without the GRANT option, a user cannot grant
  access to an object.  No configuration is required."
  describe 'A manaul review is required to ensure the Databases utilizing Discretionary Access Control (DAC) enforce a
    policy that limits propagation of access rights' do
    skip 'A manaul review is required to ensure the Databases utilizing Discretionary Access Control (DAC) enforce a
    policy that limits propagation of access rights'
  end
end
