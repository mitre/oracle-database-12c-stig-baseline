control 'V-61579' do
  title "DBMS processes or services must run under custom, dedicated OS
  accounts."
  desc "Separation of duties is a prevalent Information Technology control
  that is implemented at different layers of the information system, including
  the operating system and in applications. It serves to eliminate or reduce the
  possibility that a single user may carry out a prohibited action. Separation of
  duties requires that the person accountable for approving an action is not the
  same person who is tasked with implementing or carrying out that action.

      The DBMS must run under a custom dedicated OS account. When the DBMS is
  running under a shared account, users with access to that account could
  inadvertently or maliciously make changes to the DBMS's settings, files, or
  permissions.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000062-DB-000010'
  tag "gid": 'V-61579'
  tag "rid": 'SV-76069r1_rule'
  tag "stig_id": 'O121-C2-003400'
  tag "fix_id": 'F-67495r1_fix'
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
  tag "check": "Check OS settings to determine whether DBMS processes are
  running under a dedicated OS account. If the DBMS processes are running under
  shared accounts, this is a finding.

  This is done by the default installation.  The installation documentation
  recommends that a user account named ORACLE is created and is identified as the
  software owner.

  Log on to the system as the software owner, typically ORACLE, the $ORACLE_HOME
  environment variable will point to the Oracle software.  Enter the following
  commands to see if ORACLE is the software owner:

  $ cd $ORACLE_HOME
  $ ls -l (shows the directories - oracle is the owner and oinstall is the group.
  The example list below has been truncated)
  drwxr-xr-x  2 oracle oinstall  4096 Nov 21 08:42 addnode
  drwxr-xr-x  8 oracle oinstall  4096 Nov 21 08:41 apex
  drwxr-xr-x  9 oracle oinstall  4096 Nov 21 08:39 assistants
  drwxr-xr-x  2 oracle oinstall  4096 Nov 21 09:17 bin
  drwxr-xr-x  7 oracle oinstall  4096 Nov 21 08:42 ccr
  drwxr-xr-x  3 oracle oinstall  4096 Nov 21 08:42 cdata
  drwxr-xr-x  5 oracle oinstall  4096 Nov 21 09:04 cfgtoollogs
  drwxr-xr-x  4 oracle oinstall  4096 Nov 21 08:42 clone
  drwxr-xr-x  6 oracle oinstall  4096 Nov 21 08:39 crs
  drwxr-xr-x  6 oracle oinstall  4096 Nov 21 08:42 css
  drwxr-xr-x 11 oracle oinstall  4096 Nov 21 08:42 ctx
  drwxr-xr-x  7 oracle oinstall  4096 Nov 21 08:39 cv
  drwxr-xr-x  2 oracle oinstall  4096 Dec 16 13:11 dbs
  drwxr-xr-x  2 oracle oinstall  4096 Nov 21 08:42 dc_ocm
  drwxr-xr-x  5 oracle oinstall  4096 Nov 21 08:45 deinstall
  drwxr-xr-x  3 oracle oinstall  4096 Nov 21 08:39 demo
  drwxr-xr-x  3 oracle oinstall  4096 Nov 21 08:39 diagnostics

  $ ps -ef | grep ora_ (shows all of the oracle processes owned by the oracle
  user. The example list below has been truncated)

  oracle    1786     1  0 13:11 ?        00:00:00 ora_pmon_stig
  oracle    1788     1  0 13:11 ?        00:00:00 ora_psp0_stig
  oracle    1790     1  1 13:11 ?        00:00:08 ora_vktm_stig
  oracle    1794     1  0 13:11 ?        00:00:00 ora_gen0_stig
  oracle    1796     1  0 13:11 ?        00:00:00 ora_mman_stig
  oracle    1800     1  0 13:11 ?        00:00:00 ora_diag_stig
  oracle    1802     1  0 13:11 ?        00:00:00 ora_dbrm_stig
  oracle    1804     1  0 13:11 ?        00:00:00 ora_vkrm_stig
  oracle    1806     1  0 13:11 ?        00:00:00 ora_dia0_stig
  oracle    1808     1  0 13:11 ?        00:00:00 ora_dbw0_stig
  oracle    1810     1  0 13:11 ?        00:00:00 ora_lgwr_stig
  oracle    1812     1  0 13:11 ?        00:00:00 ora_ckpt_stig
  oracle    1814     1  0 13:11 ?        00:00:00 ora_lg00_stig
  oracle    1816     1  0 13:11 ?        00:00:00 ora_smon_stig
  oracle    1818     1  0 13:11 ?        00:00:00 ora_lg01_stig
  oracle    1820     1  0 13:11 ?        00:00:00 ora_reco_stig
  oracle    1822     1  0 13:11 ?        00:00:00 ora_lreg_stig
  oracle    1824     1  0 13:11 ?        00:00:00 ora_pxmn_stig
  oracle    2137  2125  0 13:25 pts/1    00:00:00 grep ora_"
  tag "fix": "Create an OS account dedicated to Oracle DBMS processes, and
  allow only Oracle DBMS processes to run under the account."

  oracle_file_owners = command("ls -l  $ORACLE_HOME|awk '{ print $3; }' | sort -u").stdout.strip.split("\n")

  oracle_file_owners.each do |owner|
    describe 'The file and directory inside the Oracle Home directory' do
      subject { owner }
      it { should cmp 'oracle' }
    end
  end
  if oracle_file_owners.empty?
    describe 'There are no oracle file owners, therefore this control is NA' do
      skip 'There are no oracle file owners, therefore this control is NA'
    end
  end
end
