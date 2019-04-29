control 'V-61753' do
  title "Databases employed to write data to portable digital media must use
  cryptographic mechanisms to protect and restrict access to information on
  portable digital media."
  desc "When data is written to portable digital media, such as thumb drives,
  floppy diskettes, compact disks, magnetic tape, etc., there is risk of data
  loss.

      An organizational assessment of risk guides the selection of media and
  associated information contained on that media requiring restricted access.

      Organizations need to document in policy and procedures the media requiring
  restricted access, individuals authorized to access the media, and the specific
  measures taken to restrict access. Fewer protection measures are needed for
  media containing information determined by the organization to be in the public
  domain, to be publicly releasable, or to have limited or no adverse impact if
  accessed by other than authorized personnel.

      In these situations, it is assumed the physical access controls where the
  media resides provide adequate protection. The decision whether to employ
  cryptography is the responsibility of the information owner/steward, who
  exercises discretion within the framework of applicable rules, policies, and
  law.

      The selection of the cryptographic mechanisms used is based upon
  maintaining the confidentiality and integrity of the information.

      The strength of mechanisms is commensurate with the classification and
  sensitivity of the information.

      When the organization has determined the risk warrants it, data written to
  portable digital media must be encrypted. When information written to digital
  media is not encrypted, it can be compromised.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000187-DB-000120'
  tag "gid": 'V-61753'
  tag "rid": 'SV-76243r2_rule'
  tag "stig_id": 'O121-C2-016300'
  tag "fix_id": 'F-67669r1_fix'
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
  tag "check": "If data is written to portable media, the data must be
  protected and access restricted via cryptographic mechanisms.

  Review system documentation and interview DBA to determine whether data is ever
  written directly from Oracle to portable media.

  If this is the case, and cryptographic mechanisms are not used to protect data
  written to portable media, this is a finding.

  If all data writing from Oracle to portable media is done via intermediate
  files, pipes, or other non-portable resources under the control of the
  operating system, then this is not a finding with respect to Oracle.  (Note,
  however, that if encryption is not in use, it may be a finding with respect to
  the OS or the application that is used to perform the data transfer.)"
  tag "fix": "Reconfigure processes that write to portable digital media so
  that they use cryptographic mechanisms to restrict access and protect the
  information."
  describe 'A manual review is required to ensure databases employed to write data to portable digital media use
    cryptographic mechanisms to protect and restrict access to information on
    portable digital media' do
    skip 'A manual review is required to ensure databases employed to write data to portable digital media use
    cryptographic mechanisms to protect and restrict access to information on
    portable digital media'
  end
end
