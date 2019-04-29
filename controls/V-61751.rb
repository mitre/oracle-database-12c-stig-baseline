control 'V-61751' do
  title "The DBMS must employ strong identification and authentication
  techniques when establishing nonlocal maintenance and diagnostic sessions."
  desc "Non-local maintenance and diagnostic activities are those activities
  conducted by individuals communicating through a network, either an external
  network (e.g., the Internet) or an internal network.

      The act of managing systems and applications includes the ability to access
  sensitive application information, such as system configuration details,
  diagnostic information, user information, and potentially sensitive application
  data.

      When applications provide a remote management capability inherent to the
  application, the application needs to ensure the identification and
  authentication techniques used to remotely access the system are strong enough
  to protect the system. If the communication channel is not adequately
  protected, authentication information, application data, and configuration
  information could be compromised.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000185-DB-000116'
  tag "gid": 'V-61751'
  tag "rid": 'SV-76241r1_rule'
  tag "stig_id": 'O121-C2-016100'
  tag "fix_id": 'F-67667r1_fix'
  tag "cci": ['CCI-000877']
  tag "nist": ['MA-4 c)', 'Rev_4']
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
  tag "check": "Review DBMS settings to determine whether strong identification
  and authentication techniques are required for nonlocal maintenance and
  diagnostic sessions.

  If strong identification and authentication techniques are not required, this
  is a finding."
  tag "fix": "Configure DBMS settings to use strong identification and
  authentication techniques for nonlocal maintenance and diagnostic sessions."
  describe 'A manual review is required to ensure the DBMS employs strong identification and authentication
    techniques when establishing nonlocal maintenance and diagnostic sessions' do
    skip 'A manual review is required to ensure the DBMS employs strong identification and authentication
    techniques when establishing nonlocal maintenance and diagnostic sessions'
  end
end
