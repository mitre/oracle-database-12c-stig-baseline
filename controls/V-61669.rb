control 'V-61669' do
  title "The DBMS must protect the audit records generated, as a result of
  remote access to privileged accounts, and the execution of privileged
  functions."
  desc "Protection of audit records and audit data is of critical importance.
  Care must be taken to ensure privileged users cannot circumvent audit
  protections put in place.

      Auditing might not be reliable when performed by an information system
  which the user being audited has privileged access to.

      The privileged user could inhibit auditing or directly modify audit
  records. To prevent this from occurring, privileged access shall be further
  defined between audit-related privileges and other privileges, thus limiting
  the users with audit-related privileges.

      Reducing the risk of audit compromises by privileged users can also be
  achieved, for example, by performing audit activity on a separate information
  system where the user in question has limited access or by using storage media
  that cannot be modified (e.g., write-once recording devices).

      If an attacker were to gain access to audit tools he could analyze audit
  logs for system weaknesses or weaknesses in the auditing itself.  An attacker
  could also manipulate logs to hide evidence of malicious activity.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000127-DB-000172'
  tag "gid": 'V-61669'
  tag "rid": 'SV-76159r1_rule'
  tag "stig_id": 'O121-C2-010200'
  tag "fix_id": 'F-67583r1_fix'
  tag "cci": ['CCI-000366', 'CCI-001351']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "nist": ['AU-9 (4)', 'Rev_4']
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
  tag "check": "If Standard Auditing is used:
  For table-based auditing (DB or DB,EXTENDED), review the DBMS permissions on
  the views and base tables holding the audit data.

  For file-based auditing (OS, XML, or XML,EXTENDED), review the operating
  system/file system permissions on the audit file(s).

  If permissions exist that enable unauthorized users to view audit data, this is
  a finding.

  If permissions exist that enable any user (other than an account created
  specifically to manage log space and off-load audit records to a log management
  system) to modify or delete audit records, or create spurious audit records,
  this is a finding.

  If Unified Auditing is used:
  AUDIT_ADMIN role. This role enables the creation of unified and fine-grained
  audit policies, use the AUDIT and NOAUDIT SQL statements, view audit data, and
  manage the audit trail administration. Grant this role only to trusted users.




  AUDIT_VIEWER role. This role enables users to view and analyze audit data. The
  kind of user who needs this role is typically an external auditor.

  Check to ensure the authorized users have the correct roles. If permissions
  exist that enable unauthorized users to view audit data, this is a finding.

  If permissions exist that enable any user (other than an account created
  specifically to manage log space and off-load audit records to a log management
  system) to modify or delete audit records, or create spurious audit records,
  this is a finding."
  tag "fix": "If Standard Auditing is used:
  Add controls and modify permissions to protect database audit log records from
  modification, deletion, spurious creation, or unauthorized viewing.

  If Unified Auditing is used:
  Grant the correct Audit roles to authorized users."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  users_allowed_access_to_audit_info = sql.query("SELECT GRANTEE, TABLE_NAME, PRIVILEGE
      FROM DBA_TAB_PRIVS where owner='AUDSYS';").column('grantee').uniq
  if users_allowed_access_to_audit_info.empty?
    impact 0.0
    describe 'There are no oracle users allowed access to audit information, control N/A' do
      skip 'There are no oracle users allowed access to audit information'
    end
  else
    users_allowed_access_to_audit_info.each do |user|
      describe "oracle users: #{user} allowed access to audit information" do
        subject { user }
        it { should be_in input('allowed_audit_users') }
      end
    end
  end
end
