"""The audit log is hash-chained: edits, removals, reordering and a cut-off
tail are all reported by verify()."""

from sqlalchemy import delete, select, update

from phishhawk.server import audit
from phishhawk.server.db import transaction
from phishhawk.server.models import AuditHead, AuditRecord


def _three(db):
    with transaction(db) as s:
        audit.record(s, "admin", "login", workspace_id=1)
        audit.record(s, "admin", "submit", "submission", 1, {"source": "upload"}, workspace_id=1)
        audit.record(s, "system", "analyze", "analysis", 1, {"providers": []}, workspace_id=1)


def test_an_untouched_log_verifies(db):
    _three(db)
    with transaction(db) as s:
        assert audit.verify(s) == []
        assert s.scalars(select(AuditHead)).one().count == 3


def test_an_edited_record_is_reported(db):
    _three(db)
    with transaction(db) as s:
        s.execute(update(AuditRecord).where(AuditRecord.id == 2).values(actor="someone-else"))
    with transaction(db) as s:
        assert audit.verify(s) == ["record 2 was changed"]


def test_a_removed_record_is_reported(db):
    _three(db)
    with transaction(db) as s:
        s.execute(delete(AuditRecord).where(AuditRecord.id == 2))
    with transaction(db) as s:
        assert "record 3 does not follow the one before it" in audit.verify(s)


def test_a_cut_off_tail_is_reported(db):
    _three(db)
    with transaction(db) as s:
        s.execute(delete(AuditRecord).where(AuditRecord.id == 3))
    with transaction(db) as s:
        assert audit.verify(s) == ["the newest records are missing (3 recorded, 2 found)"]


def test_reordered_records_are_reported(db):
    _three(db)
    with transaction(db) as s:
        for old, new in ((2, 99), (3, 2), (99, 3)):
            s.execute(update(AuditRecord).where(AuditRecord.id == old).values(id=new))
    with transaction(db) as s:
        assert "record 2 does not follow the one before it" in audit.verify(s)
