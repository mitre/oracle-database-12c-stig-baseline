ALLOWED_DBAOBJECT_OWNERS = input('allowed_dbaobject_owners')
control 'V-61673' do
  title 'Database objects must be owned by accounts authorized for ownership.'
  desc  "Within the database, object ownership implies full privileges to the
  owned object including the privilege to assign access to the owned objects to
  other subjects. Unmanaged or uncontrolled ownership of objects can lead to
  unauthorized object grants and alterations, and unauthorized modifications to
  data.

      If critical tables or other objects rely on unauthorized owner accounts,
  these objects can be lost when an account is removed.

      It may be the case that there are accounts that are authorized to own
  synonyms, but no other objects. If this is so, it should be documented.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000133-DB-000200'
  tag "gid": 'V-61673'
  tag "rid": 'SV-76163r2_rule'
  tag "stig_id": 'O121-C2-011000'
  tag "fix_id": 'F-67587r1_fix'
  tag "cci": ['CCI-001499']
  tag "nist": ['CM-5 (6)', 'Rev_4']
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
  tag "check": "Review system documentation to identify accounts authorized to
  own database objects. Review accounts in DBMS that own objects.

  If any database objects are found to be owned by users not authorized to own
  database objects, this is a finding.

  - - - - -
  Query the object DBA_OBJECTS to show the users who own objects in the database.
   The query below will return all of the users who own objects.

  sqlplus connect as sysdba

  SQL>select owner, object_type, count(*) from dba_objects
  group by owner, object_type
  order by owner, object_type;

  If these owners are not authorized owners, select all of the objects these
  owners have generated and decide who they should belong to.  To make a list of
  all of the objects, the unauthorized owner has to perform the following query.

  SQL>select * from dba_objects where owner =&unauthorized_owner;"
  tag "fix": "Update system documentation to include list of accounts
  authorized for object ownership.

  Re-assign ownership of authorized objects to authorized object owner accounts."

  sql = oracledb_session(user: input('user'), password: input('password'), host: input('host'), service: input('service'), sqlplus_bin: input('sqlplus_bin'))

  dba_object_owners = sql.query('select DISTINCT owner from dba_objects;').column('owner').uniq
  if dba_object_owners .empty?
    impact 0.0
    describe 'There are no oracle dba object owners, control N/A' do
      skip 'There are no oracle dba object owners, control N/A'
    end
  else
    dba_object_owners .each do |owner|
      describe "oracle datbase object owner: #{owner}" do
        subject { owner }
        it { should be_in input('allowed_dbaobject_owners') }
      end
    end
  end
end
