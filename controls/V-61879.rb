control 'V-61879' do
  title "The DBMS must uniquely identify and authenticate organizational users
  (or processes acting on behalf of organizational users)."
  desc "To assure accountability and prevent unauthorized access,
  organizational users shall be identified and authenticated.

      Organizational users include organizational employees or individuals the
  organization deems to have equivalent status of employees (e.g., contractors,
  guest researchers, individuals from allied nations).

      Users (and any processes acting on behalf of users) are uniquely identified
  and authenticated for all accesses other than those accesses explicitly
  identified and documented by the organization which outlines specific user
  actions that can be performed on the information system without identification
  or authentication.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000148-DB-000103'
  tag "gid": 'V-61879'
  tag "rid": 'SV-76369r1_rule'
  tag "stig_id": 'O121-P2-012800'
  tag "fix_id": 'F-67795r1_fix'
  tag "cci": ['CCI-000764']
  tag "nist": ['IA-2', 'Rev_4']
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
  tag "check": "Review DBMS settings, OS settings, and/or enterprise-level
  authentication/access mechanism settings, and site practices, to determine
  whether organizational users are uniquely identified and authenticated when
  logging on to the system.

  If organizational users are not uniquely identified and authenticated, this is
  a finding."
  tag "fix": "Configure DBMS, OS and/or enterprise-level authentication/access
  mechanism to uniquely identify and authenticate all organizational users who
  log on to the system.  Ensure that each user has a separate account from all
  other users."
  describe 'A manual review is required to ensure the DBMS uniquely identifies and authenticates organizational users
    (or processes acting on behalf of organizational users).' do
    skip 'A manual review is required to ensure the DBMS uniquely identifies and authenticates organizational users
    (or processes acting on behalf of organizational users).'
  end
end
