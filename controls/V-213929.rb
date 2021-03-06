# encoding: UTF-8

control 'V-213929' do
  title "SQL Server must limit the number of concurrent sessions to an
organization-defined number per user for all accounts and/or account types."
  desc  "Database management includes the ability to control the number of
users and user sessions utilizing SQL Server. Unlimited concurrent connections
to SQL Server could allow a successful Denial of Service (DoS) attack by
exhausting connection resources; and a system can also fail or be degraded by
an overload of legitimate users. Limiting the number of concurrent sessions per
user is helpful in reducing these risks.

    This requirement addresses concurrent session control for a single account.
It does not address concurrent sessions by a single user via multiple system
accounts; and it does not deal with the total number of sessions across all
accounts.

    The capability to limit the number of concurrent sessions per user must be
configured in or added to SQL Server (for example, by use of a logon trigger),
when this is technically feasible. Note that it is not sufficient to limit
sessions via a web server or application server alone, because legitimate users
and adversaries can potentially connect to SQL Server by other means.

    The organization will need to define the maximum number of concurrent
sessions by account type, by account, or a combination thereof. In deciding on
the appropriate number, it is important to consider the work requirements of
the various types of users. For example, 2 might be an acceptable limit for
general users accessing the database via an application; but 10 might be too
few for a database administrator using a database management GUI tool, where
each query tab and navigation pane may count as a separate session.

    (Sessions may also be referred to as connections or logons, which for the
purposes of this requirement are synonyms.)
  "
  desc  'rationale', ''
  desc  'check', "
    Review the system documentation to determine whether any limits have been
defined. If it does not, assume a limit of 10 for database administrators and 2
for all other users.

    If a mechanism other than a logon trigger is used, verify its correct
operation by the appropriate means. If it does not work correctly, this is a
finding.

    Otherwise, determine if a logon trigger exists:

    In SQL Server Management Studio's Object Explorer tree:
    Expand [SQL Server Instance] >> Security >> Server Objects >> Triggers

    OR

    Run the query:
    SELECT name FROM master.sys.server_triggers;

    If no triggers are listed, this is a finding.

    If triggers are listed, identify the one(s) limiting the number of
concurrent sessions per user. If none are found, this is a finding. If they are
present but disabled, this is a finding.

    Examine the trigger source code for logical correctness and for compliance
with the documented limit(s). If errors or variances exist, this is a finding.

    Verify that the system does execute the trigger(s) each time a user session
is established. If it does not operate correctly for all types of user, this is
a finding.
  "
  desc  'fix', "
    Establish the limit(s) appropriate to the type(s) of user account accessing
the SQL Server instance, and record them in the system documentation. Implement
one or more logon triggers to enforce the limit(s), without exposing the
dynamic management views to general users.

    CREATE TRIGGER SQL_STIG_Connection_Limit
    ON ALL SERVER WITH EXECUTE AS 'sa' --Make sure to use the renamed SA
account here.
    FOR LOGON
    AS
    BEGIN
        IF (SELECT COUNT(1)
            FROM sys.dm_exec_sessions
            WHERE is_user_process = 1
                And original_login_name = ORIGINAL_LOGIN()
            ) > 1000 --Organizationally defined number
        BEGIN
            PRINT 'The login [' + ORIGINAL_LOGIN() + '] has exceeded the
concurrent session limit.'
            ROLLBACK;
        END
    END;

    Reference:  https://msdn.microsoft.com/en-us/library/ms189799.aspx
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag gid: 'V-213929'
  tag rid: 'SV-213929r508026_rule'
  tag stig_id: 'SQL6-D0-003600'
  tag fix_id: 'F-15144r313571_fix'
  tag cci: ['SV-93825', 'V-79119', 'CCI-000054']
  tag nist: ['AC-10']

  query = %(
    SELECT name FROM master.sys.server_triggers WHERE is_disabled = 0
  )
  sql_session = mssql_session(user: input('user'),
                              password: input('password'),
                              host: input('host'),
                              instance: input('instance'),
                              port: input('port'),
                              db_name: input('db_name'))

  describe 'Audited Result for Defined Audit Actions' do
    subject { sql_session.query(query).column('name').uniq }
    it { should_not be_empty }
  end

  describe 'This test currently has no automated tests, you must check manually' do
    skip 'A manual review of the triggers should be performed to determine whether any of them limit the number of concurrent sessions per user'
  end

end

