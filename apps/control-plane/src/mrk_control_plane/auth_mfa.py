"""Two-step sign-in with an authenticator app (TOTP) and one-time recovery codes.

* Enrolment: ``start`` makes a pending secret (kept encrypted in the SecretStore),
  ``confirm`` checks one code from the app and only then turns two-step sign-in on
  and hands out recovery codes once (only their SHA-256 digests are stored).
* Sign-in: the password step returns a signed, five-minute challenge instead of a
  session (``AuthStore.authenticate``); :meth:`TwoStep.complete_login` checks the
  code or a recovery code and opens the session.
* Every code is accepted once (the last accepted TOTP step is stored), failures
  count toward the same lockout as passwords, and everything is audited without
  ever writing a secret or a code anywhere.
"""

from __future__ import annotations

import secrets
import threading
from typing import TYPE_CHECKING, Any

from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy import update

from . import totp
from .auth import (
    MFA_POLICY_KEY,
    AuthStore,
    FieldError,
    MfaChallenge,
    Principal,
    mfa_policy_value,
    mfa_required_for,
)
from .models import User, UserMfa

if TYPE_CHECKING:
    from sqlalchemy.orm import Session as OrmSession

    from .secret_store import SecretStore

PENDING_TTL_SECONDS = 15 * 60
# An account made by single sign-on has no password it knows; it proves itself by
# having signed in recently instead.
FRESH_SESSION_SECONDS = 15 * 60


class TwoStep:
    def __init__(self, auth: AuthStore, secret_store: SecretStore | None) -> None:
        self.auth = auth
        self.secret_store = secret_store
        self._lock = threading.RLock()

    # ----- helpers --------------------------------------------------------------
    def _store(self) -> SecretStore:
        if self.secret_store is None:
            raise FieldError("mfa_unavailable", "two-step sign-in is not available",
                             status_code=503)
        return self.secret_store

    def _secret(self, reference: str | None) -> str | None:
        if not reference or self.secret_store is None:
            return None
        try:
            return self.secret_store.get(reference).get("secret")
        except (KeyError, ValueError):
            return None

    def _rate_check(self, user_id: int) -> str:
        key = f"mfa:{user_id}"
        if self.auth._rate_limited(key):
            raise FieldError("rate_limited", "Too many attempts; try again later",
                             status_code=429)
        return key

    def _reauthenticate(
        self, principal: Principal, current_password: str | None, source_ip: str | None,
        request_id: str | None, action: str,
    ) -> None:
        """Ask for the password again before a sensitive change.

        Accounts made by single sign-on have no password of their own; for them a
        session opened within the last few minutes is accepted instead.
        """
        with self.auth.db.session() as db:
            user = db.get(User, principal.user_id)
            if user is None or not user.enabled:
                raise FieldError("user_not_found", "user not found", status_code=404)
            stored_hash = user.password_hash
            sso_account = user.identity_provider == "oidc"
        if sso_account and not current_password:
            created = principal.session_created_at or 0
            if self.auth._now() - created <= FRESH_SESSION_SECONDS:
                return
            raise FieldError("reauthentication_required", "sign in again first",
                             status_code=403)
        key = f"password:{principal.user_id}"
        if self.auth._rate_limited(key):
            raise FieldError("rate_limited", "Too many attempts; try again later",
                             status_code=429)
        valid = False
        if current_password:
            try:
                valid = self.auth._verify_password(stored_hash, current_password)
            except (VerifyMismatchError, InvalidHashError):
                valid = False
        if not valid:
            self.auth._record_attempt(key)
            self.auth.record_audit(principal.user_id, action, "user", str(principal.user_id),
                                   "failure", source_ip, request_id)
            raise FieldError("invalid_current_password", "current password is not correct",
                             "current_password", "incorrect", status_code=422)
        self.auth._clear_attempts(key)

    @staticmethod
    def _row(db: OrmSession, user_id: int, now: int) -> UserMfa:
        row = db.get(UserMfa, user_id)
        if row is None:
            row = UserMfa(user_id=user_id, last_step=0, recovery_hashes=[], updated_at=now)
            db.add(row)
        return row

    def _check_code(
        self, db: OrmSession, row: UserMfa, user_id: int, code: str | None,
        recovery_code: str | None,
    ) -> str | None:
        """'totp' or 'recovery' when the code is right (and now used up), else None."""
        now = self.auth._now()
        if code:
            secret = self._secret(row.secret_ref)
            if secret is None:
                return None
            step = totp.matching_step(secret, code, now, int(row.last_step or 0))
            if step is None:
                return None
            # Conditional update: two requests racing with the same code cannot both win.
            result = db.execute(
                update(UserMfa)
                .where(UserMfa.user_id == user_id, UserMfa.last_step < step)
                .values(last_step=step, updated_at=now)
            )
            if not result.rowcount:
                return None
            db.refresh(row)
            return "totp"
        if recovery_code:
            digest = totp.recovery_hash(user_id, recovery_code)
            remaining = list(row.recovery_hashes or [])
            match = next(
                (item for item in remaining if secrets.compare_digest(item, digest)), None
            )
            if match is None:
                return None
            remaining.remove(match)
            row.recovery_hashes = remaining
            row.updated_at = now
            return "recovery"
        return None

    def _new_recovery_codes(self, row: UserMfa, user_id: int, now: int) -> list[str]:
        codes = totp.new_recovery_codes()
        row.recovery_hashes = [totp.recovery_hash(user_id, code) for code in codes]
        row.recovery_generated_at = now
        row.updated_at = now
        return codes

    # ----- self service ---------------------------------------------------------
    def status(self, principal: Principal) -> dict[str, Any]:
        now = self.auth._now()
        with self.auth.db.session() as db:
            user = db.get(User, principal.user_id)
            row = db.get(UserMfa, principal.user_id)
            policy = mfa_policy_value(self.auth._setting(db, MFA_POLICY_KEY))
            enabled = bool(user is not None and user.mfa_enabled)
            return {
                "enabled": enabled,
                "method": "totp" if enabled else None,
                "enabled_at": row.enabled_at if row is not None and enabled else None,
                "recovery_codes_left": len(row.recovery_hashes or []) if row and enabled else 0,
                "recovery_generated_at": row.recovery_generated_at if row and enabled else None,
                "pending": bool(
                    row is not None and row.pending_ref
                    and (row.pending_created_at or 0) > now - PENDING_TTL_SECONDS
                ),
                "required": bool(user is not None and mfa_required_for(policy, user.role)),
                "password_required": bool(user is not None and user.identity_provider != "oidc"),
                "available": self.secret_store is not None,
            }

    def start(
        self, principal: Principal, current_password: str | None, source_ip: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, str]:
        store = self._store()
        self._reauthenticate(principal, current_password, source_ip, request_id,
                             "auth.mfa.enroll.start")
        secret = totp.new_secret()
        reference = f"mfa-pending-{principal.user_id}-{secrets.token_hex(8)}"
        now = self.auth._now()
        old_pending: str | None = None
        with self._lock:
            with self.auth.db.session() as db, db.begin():
                user = db.get(User, principal.user_id)
                if user is None:
                    raise FieldError("user_not_found", "user not found", status_code=404)
                if user.mfa_enabled:
                    raise FieldError("mfa_already_enabled", "two-step sign-in is already on",
                                     status_code=409)
                store.replace(reference, {"secret": secret})
                row = self._row(db, principal.user_id, now)
                old_pending = row.pending_ref
                row.pending_ref = reference
                row.pending_created_at = now
                row.updated_at = now
                account = user.email or user.username
                self.auth._audit_db(db, principal.user_id, "auth.mfa.enroll.start", "user",
                                    str(principal.user_id), "success", source_ip, request_id)
        if old_pending:
            self.auth.forget_secrets([old_pending])
        return {
            "secret": secret,
            "otpauth_uri": totp.otpauth_uri(secret, account),
            "issuer": totp.ISSUER,
            "account": account,
            "digits": str(totp.TOTP_DIGITS),
            "period": str(totp.TOTP_PERIOD),
        }

    def confirm(
        self, principal: Principal, code: str, source_ip: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        store = self._store()
        key = self._rate_check(principal.user_id)
        now = self.auth._now()
        forget: list[str] = []
        with self._lock:
            with self.auth.db.session() as db, db.begin():
                user = db.get(User, principal.user_id)
                row = db.get(UserMfa, principal.user_id)
                if user is None or row is None or not row.pending_ref or (
                    (row.pending_created_at or 0) <= now - PENDING_TTL_SECONDS
                ):
                    raise FieldError("mfa_enrollment_expired",
                                     "start setting up two-step sign-in again", status_code=409)
                if user.mfa_enabled:
                    raise FieldError("mfa_already_enabled", "two-step sign-in is already on",
                                     status_code=409)
                secret = self._secret(row.pending_ref)
                step = (
                    totp.matching_step(secret, code, now, 0) if secret is not None else None
                )
                if step is None:
                    self.auth._record_attempt(key)
                    self.auth._audit_db(db, principal.user_id, "auth.mfa.enroll.confirm", "user",
                                        str(principal.user_id), "failure", source_ip, request_id)
                    failed = True
                else:
                    failed = False
                    final_ref = f"mfa-totp-{principal.user_id}-{secrets.token_hex(8)}"
                    store.replace(final_ref, {"secret": secret or ""})
                    forget = [ref for ref in (row.secret_ref, row.pending_ref) if ref]
                    row.secret_ref = final_ref
                    row.pending_ref = None
                    row.pending_created_at = None
                    row.enabled_at = now
                    row.last_step = step
                    codes = self._new_recovery_codes(row, principal.user_id, now)
                    user.mfa_enabled = True
                    user.updated_at = now
                    # Other browsers were signed in with the password alone.
                    self.auth._revoke_sessions(db, principal.user_id, now,
                                               keep_session_id=principal.session_id)
                    self.auth._audit_db(db, principal.user_id, "auth.mfa.enable", "user",
                                        str(principal.user_id), "success", source_ip, request_id)
        if failed:
            raise FieldError("invalid_mfa_code", "the code is not right", "code", "incorrect",
                             status_code=422)
        self.auth._clear_attempts(key)
        self.auth.forget_secrets(forget)
        return {"enabled": True, "recovery_codes": codes}

    def regenerate_recovery_codes(
        self, principal: Principal, code: str | None, recovery_code: str | None = None,
        source_ip: str | None = None, request_id: str | None = None,
    ) -> dict[str, Any]:
        key = self._rate_check(principal.user_id)
        now = self.auth._now()
        with self._lock:
            with self.auth.db.session() as db, db.begin():
                user = db.get(User, principal.user_id)
                row = db.get(UserMfa, principal.user_id)
                if user is None or row is None or not user.mfa_enabled:
                    raise FieldError("mfa_not_enabled", "two-step sign-in is off",
                                     status_code=409)
                used = self._check_code(db, row, principal.user_id, code, recovery_code)
                if used is None:
                    self.auth._record_attempt(key)
                    self.auth._audit_db(db, principal.user_id, "auth.mfa.recovery.regenerate",
                                        "user", str(principal.user_id), "failure", source_ip,
                                        request_id)
                    codes: list[str] = []
                else:
                    codes = self._new_recovery_codes(row, principal.user_id, now)
                    self.auth._audit_db(db, principal.user_id, "auth.mfa.recovery.regenerate",
                                        "user", str(principal.user_id), "success", source_ip,
                                        request_id)
        if not codes:
            raise FieldError("invalid_mfa_code", "the code is not right", "code", "incorrect",
                             status_code=422)
        self.auth._clear_attempts(key)
        return {"recovery_codes": codes}

    def disable(
        self, principal: Principal, current_password: str | None, code: str | None,
        recovery_code: str | None = None, source_ip: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        self._reauthenticate(principal, current_password, source_ip, request_id,
                             "auth.mfa.disable")
        key = self._rate_check(principal.user_id)
        now = self.auth._now()
        forget: list[str] = []
        with self._lock:
            with self.auth.db.session() as db, db.begin():
                user = db.get(User, principal.user_id)
                row = db.get(UserMfa, principal.user_id)
                if user is None or row is None or not user.mfa_enabled:
                    raise FieldError("mfa_not_enabled", "two-step sign-in is off",
                                     status_code=409)
                policy = mfa_policy_value(self.auth._setting(db, MFA_POLICY_KEY))
                if mfa_required_for(policy, user.role):
                    raise FieldError("mfa_required_by_policy",
                                     "two-step sign-in is required for your role",
                                     status_code=409)
                used = self._check_code(db, row, principal.user_id, code, recovery_code)
                if used is None:
                    self.auth._record_attempt(key)
                    self.auth._audit_db(db, principal.user_id, "auth.mfa.disable", "user",
                                        str(principal.user_id), "failure", source_ip, request_id)
                    failed = True
                else:
                    failed = False
                    forget = [ref for ref in (row.secret_ref, row.pending_ref) if ref]
                    db.delete(row)
                    user.mfa_enabled = False
                    user.updated_at = now
                    self.auth._audit_db(db, principal.user_id, "auth.mfa.disable", "user",
                                        str(principal.user_id), "success", source_ip, request_id)
        if failed:
            raise FieldError("invalid_mfa_code", "the code is not right", "code", "incorrect",
                             status_code=422)
        self.auth._clear_attempts(key)
        self.auth.forget_secrets(forget)
        return {"enabled": False}

    # ----- people management ------------------------------------------------------
    def admin_reset(
        self, user_id: int, actor: Principal, source_ip: str | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Turn someone's two-step sign-in off (lost phone). Same guards as other changes."""
        if user_id == actor.user_id:
            raise FieldError("cannot_reset_self", "turn your own two-step sign-in off instead",
                             "user_id", "self", status_code=409)
        now = self.auth._now()
        forget: list[str] = []
        with self._lock:
            with self.auth.db.session() as db, db.begin():
                user = self.auth._lifecycle_target(db, user_id, actor)
                row = db.get(UserMfa, user_id)
                if row is not None:
                    forget = [ref for ref in (row.secret_ref, row.pending_ref) if ref]
                    db.delete(row)
                was_enabled = bool(user.mfa_enabled)
                user.mfa_enabled = False
                user.updated_at = now
                self.auth._audit_db(db, actor.user_id, "user.mfa.reset", "user", str(user_id),
                                    "success" if was_enabled else "noop", source_ip, request_id)
        self.auth.forget_secrets(forget)
        self.auth._clear_attempts(f"mfa:{user_id}")
        return {"user_id": user_id, "enabled": False, "was_enabled": was_enabled}

    # ----- sign-in ----------------------------------------------------------------
    def complete_login(
        self,
        challenge: str,
        code: str | None,
        recovery_code: str | None,
        source_ip: str | None,
        request_id: str | None,
        *,
        remember: bool | None = None,
        user_agent: str | None = None,
    ) -> tuple[str, str, Principal, dict[str, Any]]:
        payload = self.auth.read_mfa_challenge(challenge)
        if payload is None:
            self.auth.record_audit(None, "auth.login.mfa", "session", None, "invalid_challenge",
                                   source_ip, request_id)
            raise FieldError("mfa_challenge_invalid", "sign in again", status_code=401)
        user_id = int(payload["u"])
        key = f"mfa:{user_id}"
        if self.auth._rate_limited(key):
            self.auth.record_audit(user_id, "auth.login.mfa", "session", None, "rate_limited",
                                   source_ip, request_id)
            raise FieldError("rate_limited", "Too many attempts; try again later",
                             status_code=429)
        if not (code or recovery_code):
            raise FieldError("invalid_mfa_code", "enter the code", "code", "required",
                             status_code=422)
        with self._lock:
            with self.auth.db.session() as db, db.begin():
                user = db.get(User, user_id)
                row = db.get(UserMfa, user_id)
                valid_user = (
                    user is not None and user.enabled and user.mfa_enabled and row is not None
                    and secrets.compare_digest(
                        str(payload.get("p", "")),
                        self.auth.password_fingerprint(user.password_hash),
                    )
                    and self.auth._role_permissions_db(db, user.role) is not None
                )
                if not valid_user:
                    self.auth._audit_db(db, user_id, "auth.login.mfa", "session", None,
                                        "invalid_challenge", source_ip, request_id)
                    outcome: Any = "invalid_challenge"
                else:
                    assert user is not None and row is not None  # noqa: S101 - narrowed above
                    used = self._check_code(db, row, user_id, code, recovery_code)
                    if used is None:
                        self.auth._record_attempt(key)
                        self.auth._audit_db(db, user_id, "auth.login.mfa", "session", None,
                                            "failure", source_ip, request_id)
                        outcome = "failure"
                    elif not self.auth.consume_mfa_challenge(payload):
                        outcome = "invalid_challenge"
                    else:
                        if used == "recovery":
                            self.auth._audit_db(db, user_id, "auth.mfa.recovery.use", "user",
                                                str(user_id), "success", source_ip, request_id)
                        method = "oidc+mfa" if payload.get("m") == "oidc" else "password+mfa"
                        keep = bool(payload.get("r")) if remember is None else remember
                        token, csrf, principal = self.auth._open_session(
                            db, user, source_ip, request_id, remember=keep, method=method,
                            user_agent=user_agent,
                        )
                        outcome = (token, csrf, principal, {
                            "method": used,
                            "recovery_codes_left": len(row.recovery_hashes or []),
                        })
        if outcome == "invalid_challenge":
            raise FieldError("mfa_challenge_invalid", "sign in again", status_code=401)
        if outcome == "failure":
            raise FieldError("invalid_mfa_code", "the code is not right", "code", "incorrect",
                             status_code=401)
        self.auth._clear_attempts(key)
        return outcome

    def challenge_for(self, user: User, *, remember: bool, method: str) -> MfaChallenge:
        return self.auth.issue_mfa_challenge(user, remember=remember, method=method)
