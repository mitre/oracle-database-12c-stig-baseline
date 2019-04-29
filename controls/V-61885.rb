control 'V-61885' do
  title "The DBMS must prevent the presentation of information system
  management-related functionality at an interface utilized by general (i.e.,
  non-privileged) users."
  desc "Information system management functionality includes functions
  necessary to administer databases, network components, workstations, or
  servers, and typically requires privileged user access.

      The separation of user functionality from information system management
  functionality is either physical or logical and is accomplished by using
  different computers, different central processing units, different instances of
  the operating system, different network addresses, combinations of these
  methods, or other methods, as appropriate.

      An example of this type of separation is observed in web administrative
  interfaces that use separate authentication methods for users of any other
  information system resources. This may include isolating the administrative
  interface on a different domain and with additional access controls.

      If administrative functionality or information regarding DBMS management is
  presented on an interface available for users, information on DBMS settings may
  be inadvertently made available to the user.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000212-DB-000123'
  tag "gid": 'V-61885'
  tag "rid": 'SV-76375r1_rule'
  tag "stig_id": 'O121-P2-017400'
  tag "fix_id": 'F-67801r1_fix'
  tag "cci": ['CCI-001083']
  tag "nist": ['SC-2 (1)', 'Rev_4']
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
  tag "check": "Check DBMS settings and vendor documentation to verify
  administrative functionality is separate from user functionality.

  If administrator and general user functionality is not separated either
  physically or logically, this is a finding."
  tag "fix": "Configure DBMS settings to separate database administration and
  general user functionality.  Provide those who have both administrative and
  general-user responsibilities with separate accounts for these separate
  functions."
  describe 'A manual review is required to ensure the DBMS prevents the presentation of information system
    management-related functionality at an interface utilized by general (i.e.,
    non-privileged) users.' do
    skip 'A manual review is required to ensure the DBMS prevents the presentation of information system
    management-related functionality at an interface utilized by general (i.e.,
    non-privileged) users.'
  end
end
