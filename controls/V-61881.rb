control 'V-61881' do
  title "The DBMS must uniquely identify and authenticate non-organizational
  users (or processes acting on behalf of non-organizational users)."
  desc  "Non-organizational users include all information system users other
  than organizational users which include organizational employees or individuals
  the organization deems to have equivalent status of employees (e.g.,
  contractors, guest researchers, individuals from allied nations).

      Non-organizational users shall be uniquely identified and authenticated for
  all accesses other than those accesses explicitly identified and documented by
  the organization when related to the use of anonymous access, such as accessing
  a web server.

      Accordingly, a risk assessment is used in determining the authentication
  needs of the organization.

      Scalability, practicality, and security are simultaneously considered in
  balancing the need to ensure ease of use for access to federal information and
  information systems with the need to protect and adequately mitigate risk to
  organizational operations, organizational assets, individuals, other
  organizations, and the Nation.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000180-DB-000115'
  tag "gid": 'V-61881'
  tag "rid": 'SV-76371r1_rule'
  tag "stig_id": 'O121-P2-015800'
  tag "fix_id": 'F-67797r1_fix'
  tag "cci": ['CCI-000804']
  tag "nist": ['IA-8', 'Rev_4']
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
  tag "check": "Review DBMS settings to determine whether non-organizational
  users are uniquely identified and authenticated when logging onto the system.

  If non-organizational users are not uniquely identified and authenticated, this
  is a finding."
  tag "fix": "Configure DBMS settings to uniquely identify and authenticate all
  non-organizational users who log onto the system."
  describe 'A manual review is required to ensure the DBMS uniquely identifies and authenticates non-organizational
  users (or processes acting on behalf of non-organizational users).' do
    skip 'A manual review is required to ensure the DBMS uniquely identifies and authenticates non-organizational
    users (or processes acting on behalf of non-organizational users).'
  end
end
