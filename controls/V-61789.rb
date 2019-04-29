control 'V-61789' do
  title 'The DBMS must identify potentially security-relevant error conditions.'
  desc  "The structure and content of error messages need to be carefully
  considered by the organization and development team. The extent to which the
  application is able to identify and handle error conditions is guided by
  organizational policy and operational requirements.

      Database logs can be monitored for specific security-related errors. Any
  error that can have a negative effect on database security should be quickly
  identified and forwarded to the appropriate personnel.  If security-relevant
  error conditions are not identified by the DBMS, they may be overlooked by the
  personnel responsible for addressing them.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000265-DB-000161'
  tag "gid": 'V-61789'
  tag "rid": 'SV-76279r1_rule'
  tag "stig_id": 'O121-C2-019800'
  tag "fix_id": 'F-67705r1_fix'
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
  tag "check": "Check DBMS settings to determine whether security-related error
  conditions are monitored for, and whether appropriate personnel are notified.

  If security-related error conditions are not being monitored for, this is a
  finding.

  If appropriate personnel are not alerted when a security-related error
  condition is found, this is a finding."
  tag "fix": "Configure DBMS to monitor for security-related error conditions.

  Configure DBMS to alert appropriate personnel when security-related error
  conditions are found.

  This can be accomplished by using Oracle Audit Vault and/or Oracle Enterprise
  Manager. If neither of these products is deployed, then develop a site-specific
  solution.

  - - - - -
  Notes to assist in developing a site-specific solution:

  The AUD$ table has a column called RETURNCODE.  That column provides the return
  code; so, for example, if the security-related condition is someone trying to
  select data from a table that is not there, it would show up in the AUD$ table
  as an ORA-00942 - table or view does not exist.  Since the RETURNCODE column is
  only numeric, only the 00942 would be stored. If the query for the information
  returned a row, the process would then need to form and send an email message.

  Oracle recommends the use of Oracle Audit Vault to fill this requirement
  without creating a custom solution.   It is possible to set up notifications
  and alerts in Enterprise Manager as well, and if either of these alternatives
  is not available, a custom solution will be necessary."
  describe 'A manual review is required to ensure the DBMS must identifies potentially security-relevant error conditions' do
    skip 'A manual review is required to ensure the DBMS must identifies potentially security-relevant error conditions'
  end
end
