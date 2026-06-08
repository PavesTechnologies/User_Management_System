DATE : 09/03/2026
here's a summary of all changes made to your User Management System (UMS):

Redis / Token Blacklist
Fixed Redis connection dropping silently by adding health_check_interval=30
Replaced permanent _redis_available = False flag with a 30-second retry window so Redis self-heals after blips
Added in-memory blacklist cache so most requests never hit Redis at all

JWT Validator
Wrapped is_token_blacklisted() in try/except so Redis failures never cause a 401
Ensured HTTPException from revoked tokens still propagates correctly

Token Creation
Cached decrypted JWT keys in memory with 5-minute TTL using timestamp instead of a boolean flag
Fixed get_jwt_keys() which was calling set_db_session() (opening a new DB connection on every login) — changed to reuse the existing request session

Login Service & DAO

Added get_user_login_data() DAO method combining 4 separate DB queries (user, roles, group_ids, permissions) into 2 queries using a single joined query
Updated login_user() service to use the new combined method and pass existing DB session to token_create()

Result
Before:  26,507ms per login (server)
After:    6,113ms per login (server)
Local:      895ms per login

DATE: 08/06/2026
testing ci (python shared lib pipeline test)
