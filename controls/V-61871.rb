control 'V-61871' do
  title "The DBMS must provide the ability to write specified audit record
  content to a centralized audit log repository."
  desc "Information system auditing capability is critical for accurate
  forensic analysis. Audit record content that may be necessary to satisfy the
  requirement of this control includes but is not limited:  timestamps, source
  and destination IP addresses, user/process identifiers, event descriptions,
  application specific events, success/fail indications, file names involved,
  access control or flow control rules invoked.

      Centralized management of audit records and logs provides for efficiency in
  maintenance and management of records, as well as, the backup and archiving of
  those records. When organizations define application components requiring
  centralized audit log management, applications need to support that requirement.

      Database audit records not stored in a centralized audit log management
  tool may be overlooked during investigation of a security incident or may be
  subject to intentional or accidental manipulation by privileged users of the
  database.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000102-DB-000045'
  tag "gid": 'V-61871'
  tag "rid": 'SV-76361r1_rule'
  tag "stig_id": 'O121-P2-008100'
  tag "fix_id": 'F-67787r1_fix'
  tag "cci": ['CCI-001844']
  tag "nist": ['AU-3 (2)', 'Rev_4']
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
  tag "check": "If the organization does not require the use of a centralized
  audit log repository, this is not a finding.

  If the organization requires the use of a centralized audit log repository,
  continue.

  Check that Oracle PL/SQL code or other software is in place to copy or transfer
  the specified audit record content to a centralized audit log repository.  If
  it is not, this is a finding.

  Check that permissions are set on the Oracle audit trail tables and on the
  target repository to enable the required transfer of audit data.  If they are
  not, this is a finding.

  Verify that the specified audit record content is indeed copied or transferred
  to the central repository.  If it is not, this is a finding."
  tag "fix": "If the organization requires the use of a centralized audit log
  repository, employ PL/SQL code or other software to copy or transfer the
  specified audit record content to the repository.

  Ensure that permissions are set to enable transfer of the data.

  If, after the preceding steps, the transfer is not succeeding, diagnose and
  repair the problem.

  For more information on the configuration of auditing, refer to the following
  documents:
  \"Auditing Database Activity\" in the Oracle Database 2 Day + Security Guide:
  http://docs.oracle.com/database/121/TDPSG/tdpsg_auditing.htm#TDPSG50000
  \"Monitoring Database Activity with Auditing\" in the Oracle Database Security
  Guide:
  http://docs.oracle.com/database/121/DBSEG/part_6.htm#CCHEHCGI
  \"DBMS_AUDIT_MGMT\" in the Oracle Database PL/SQL Packages and Types Reference:
  http://docs.oracle.com/database/121/ARPLS/d_audit_mgmt.htm#ARPLS241"
  describe 'A manual review is required to ensure the DBMS provides the ability to write specified audit record
    content to a centralized audit log repository' do
    skip 'A manual review is required to ensure the DBMS provides the ability to write specified audit record
    content to a centralized audit log repository'
  end
end
