control 'V-61581' do
  title "The DBMS must restrict grants to sensitive information to authorized
  user roles."
  desc "Applications employ the concept of least privilege for specific duties
  and information systems (including specific functions, ports, protocols, and
  services). The concept of least privilege is also applied to information system
  processes, ensuring that the processes operate at privilege levels no higher
  than necessary to accomplish required organizational missions and/or functions.
  Organizations consider the creation of additional processes, roles, and
  information system accounts as necessary to achieve least privilege.
  Organizations also apply least privilege concepts to the design, development,
  implementation, and operations of information systems.

      Unauthorized access to sensitive data may compromise the confidentiality of
  personnel privacy, threaten national security, or compromise a variety of other
  sensitive operations. Access controls are best managed by defining requirements
  based on distinct job functions and assigning access based on the job function
  assigned to the individual user.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000062-DB-000011'
  tag "gid": 'V-61581'
  tag "rid": 'SV-76071r1_rule'
  tag "stig_id": 'O121-C2-003500'
  tag "fix_id": 'F-67497r1_fix'
  tag "cci": ['CCI-000366', 'CCI-002220']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "nist": ['AC-5 c', 'Rev_4']
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
  tag "check": "Obtain a list of privileges assigned to user accounts. If
  access to sensitive information is granted to roles not authorized to access
  sensitive information, this is a finding.

  If access to sensitive information is granted to individual accounts rather
  than to a role, this is a finding."
  tag "fix": "Define application user roles based on privilege and job function
  requirements.

  Assign the required privileges to the role and assign the role to authorized
  application user accounts.

  Revoke any privileges to sensitive information directly assigned to application
  user accounts."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  database_roles = sql.query('select * from dba_roles;').column('role')

  describe "A manual review is required to ensure the DBMS estricts grants to sensitive information to authorized user roles. The database roles to review are: #{database_roles}" do
    skip "A manual review is required to ensure the DBMS estricts grants to sensitive information to authorized user roles. The database roles to review are: #{database_roles}"
  end
end
