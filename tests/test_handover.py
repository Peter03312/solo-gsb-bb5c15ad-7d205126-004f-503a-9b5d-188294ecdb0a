"""封存人交接（handover）功能测试。

规则要点（规格）：
- 封存人可为未开封资料向另一名本地账号发起交接邀请：受让人账号 + 带时区的
  确认截止时刻；受让人须已注册、不是封存人本人或当前见证人；
- 每份资料同时至多一份待确认（pending）且未过期邀请；
- 封存人可撤回未确认邀请；受让人须在截止前凭本人 X-API-Key 确认；
- 已撤回/逾期/已确认的邀请不能确认；逾期或撤回后可重新邀请；
- 确认时先结算到点开封与请求到期：资料已开封则拒绝交接；否则进行中的
  开封请求置 invalidated、旧同意全部删除，再转移封存人身份；见证名单、
  正文、摘要不变；
- 确认/撤回的截止判定以取得写锁后的实际时刻为准：等待写锁期间越过确认
  截止时刻的，邀请先置 expired 并留逾期审计（随事务提交），再沿用 409
  拒绝——确认不转移身份/不失效旧请求/不发交接通知，撤回不改成 revoked，
  处理时刻反映实际结算时刻；截止前取锁仍按原规则完成；
- 交接后原封存人失去查看/操作权限，新封存人可重新申请开封；开封前任何
  响应（含错误体）不得泄露正文；
- 成功操作返回邀请状态；确认还返回当前封存人与旧请求结果；
- 无权或无效邀请一律拒绝且不泄露资料；成功交接与请求失效均留审计；
- 并发确认/撤回/见证同意/定时处理按已提交顺序产生唯一结果。
"""
import contextlib
import datetime as dt
import os
import sqlite3
import threading
import time

import pytest

from conftest import auth, register, seal

BODY = "交接绝密资料 HANDOVER-SECRET"


def _in_hours(h: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=h)).isoformat()


def _in_seconds(s: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=s)).isoformat()


def _setup(client, names=("owner", "w1", "w2", "w3", "new", "other")):
    keys = {n: register(client, n) for n in names}
    d = seal(client, keys["owner"], BODY, ["w1", "w2", "w3"])
    return keys, d["document_id"], d["digest"]


def _invite(client, owner_key, doc_id, to_name, deadline_hours=1):
    return client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": to_name, "confirm_deadline": _in_hours(deadline_hours)},
        headers=auth(owner_key),
    )


def _confirm(client, key, inv_id):
    return client.post(f"/handover-invitations/{inv_id}/confirm", headers=auth(key))


def _revoke(client, key, inv_id):
    return client.post(f"/handover-invitations/{inv_id}/revoke", headers=auth(key))


def _get_inv(client, key, inv_id):
    return client.get(f"/handover-invitations/{inv_id}", headers=auth(key))


def _create_request(client, owner_key, doc_id, *, deadline_h=2, earliest=None):
    payload = {"reason": "交接测试", "deadline": _in_hours(deadline_h)}
    if earliest is not None:
        payload["earliest_open_at"] = _in_seconds(earliest)
    r = client.post(
        f"/documents/{doc_id}/open-requests", json=payload, headers=auth(owner_key)
    )
    assert r.status_code == 201, r.text
    return r.json()["request_id"]


def _approve(client, key, req, dg):
    return client.post(
        f"/open-requests/{req}/approve", json={"digest": dg}, headers=auth(key)
    )


# ---------------------------------------------------------------------------
# 发起邀请：创建与校验
# ---------------------------------------------------------------------------


def test_create_invitation_returns_pending_status(client):
    keys, doc_id, _ = _setup(client)
    r = _invite(client, keys["owner"], doc_id, "new")
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["status"] == "pending"
    assert data["from_username"] == "owner"
    assert data["to_username"] == "new"
    assert data["document_id"] == doc_id
    assert data["resolved_at"] is None
    assert "confirm_deadline" in data and data["confirm_deadline"].endswith("+00:00")
    # 成功响应只含元数据，不含正文/摘要
    assert BODY not in r.text and "digest" not in r.json()

    records = client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])).json()["records"]
    assert records[-1]["action"] == "handover_invited"


def test_create_invitation_validation(client):
    keys, doc_id, _ = _setup(client)
    future = _in_hours(1)

    # 受让人未注册 -> 400
    assert _invite(client, keys["owner"], doc_id, "ghost").status_code == 400
    # 受让人是封存人本人 -> 400
    assert _invite(client, keys["owner"], doc_id, "owner").status_code == 400
    # 受让人是当前见证人 -> 400
    assert _invite(client, keys["owner"], doc_id, "w1").status_code == 400
    # 截止时刻已过 -> 400
    r = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": "2020-01-01T00:00:00Z"},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 400
    # 不带时区 -> 422
    r = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": "2026-10-01T12:00:00"},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 422 and BODY not in r.text
    # 缺少字段 -> 422
    r = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new"},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 422

    # 无一份邀请被创建：之后仍可正常发起
    assert _invite(client, keys["owner"], doc_id, "new").status_code == 201


def test_create_invitation_requires_current_owner(client):
    keys, doc_id, _ = _setup(client)
    future = _in_hours(1)
    payload = {"to_username": "new", "confirm_deadline": future}
    # 见证人 / 无关账号 -> 403（不区分资料是否存在）
    assert client.post(
        f"/documents/{doc_id}/handover-invitations", json=payload, headers=auth(keys["w1"])
    ).status_code == 403
    assert client.post(
        f"/documents/999/handover-invitations", json=payload, headers=auth(keys["other"])
    ).status_code == 403
    # 无密钥 / 坏密钥 -> 401
    assert client.post(
        f"/documents/{doc_id}/handover-invitations", json=payload
    ).status_code == 401
    assert client.post(
        f"/documents/{doc_id}/handover-invitations", json=payload, headers=auth("deadbeef")
    ).status_code == 401


def test_only_one_pending_invitation_per_document(client):
    keys, doc_id, _ = _setup(client)
    assert _invite(client, keys["owner"], doc_id, "new").status_code == 201
    # 第二份待确认邀请（无论受让人是谁）-> 409
    r = _invite(client, keys["owner"], doc_id, "other")
    assert r.status_code == 409 and BODY not in r.text

    # 撤回后可重新邀请
    inv = _get_inv(client, keys["owner"], 1).json()["invitation_id"]
    assert _revoke(client, keys["owner"], inv).status_code == 200
    r = _invite(client, keys["owner"], doc_id, "other")
    assert r.status_code == 201 and r.json()["to_username"] == "other"


# ---------------------------------------------------------------------------
# 撤回
# ---------------------------------------------------------------------------


def test_revoke_pending_invitation(client):
    keys, doc_id, _ = _setup(client)
    inv_id = _invite(client, keys["owner"], doc_id, "new").json()["invitation_id"]

    # 受让人/见证人/外人不能撤回
    assert _revoke(client, keys["new"], inv_id).status_code == 403
    assert _revoke(client, keys["w1"], inv_id).status_code == 403
    assert _revoke(client, keys["other"], inv_id).status_code == 403
    assert _revoke(client, keys["owner"], 9999).status_code == 403

    r = _revoke(client, keys["owner"], inv_id)
    assert r.status_code == 200 and r.json()["status"] == "revoked"

    # 已撤回不能再撤回 / 确认
    assert _revoke(client, keys["owner"], inv_id).status_code == 409
    assert _confirm(client, keys["new"], inv_id).status_code == 409

    # 撤回后可重新邀请
    assert _invite(client, keys["owner"], doc_id, "new").status_code == 201

    records = client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])).json()["records"]
    assert [r["action"] for r in records].count("handover_revoked") == 1


# ---------------------------------------------------------------------------
# 逾期
# ---------------------------------------------------------------------------


def test_expired_invitation_cannot_confirm_and_can_reinvite(client, sweep):
    keys, doc_id, _ = _setup(client)
    r = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_seconds(1)},
        headers=auth(keys["owner"]),
    )
    inv_id = r.json()["invitation_id"]
    time.sleep(1.15)
    assert sweep() == 0  # 返回的是过期开封请求数；邀请逾期不计数但已处理

    got = _get_inv(client, keys["new"], inv_id).json()
    assert got["status"] == "expired"

    # 逾期不能确认，也不能撤回
    assert _confirm(client, keys["new"], inv_id).status_code == 409
    assert _revoke(client, keys["owner"], inv_id).status_code == 409

    # 逾期后可重新邀请
    r = _invite(client, keys["owner"], doc_id, "new")
    assert r.status_code == 201 and r.json()["status"] == "pending"

    records = client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])).json()["records"]
    assert "handover_invitation_expired" in [r["action"] for r in records]


@pytest.fixture
def passive_client(tmp_path, monkeypatch):
    """后台扫描间隔拉到 1 小时：验证写临界区自行做逾期/到点判定。"""
    monkeypatch.setenv("SEAL_DB_PATH", str(tmp_path / "passive-handover.db"))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", "3600")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


def test_confirm_after_deadline_rejected_without_sweep(passive_client):
    """无后台扫描时，确认临界区自行做逾期判定，绝不超期确认。"""
    c = passive_client
    keys, doc_id, _ = _setup(c)
    inv_id = c.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_seconds(1)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]
    time.sleep(1.15)
    r = _confirm(c, keys["new"], inv_id)
    assert r.status_code == 409 and BODY not in r.text
    # 身份未转移
    assert c.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).status_code == 200
    assert c.get(f"/documents/{doc_id}", headers=auth(keys["new"])).status_code == 403
    assert _get_inv(c, keys["new"], inv_id).json()["status"] == "expired"


# ---------------------------------------------------------------------------
# 确认交接
# ---------------------------------------------------------------------------


def test_confirm_without_active_request_transfers_ownership(client):
    keys, doc_id, _ = _setup(client)
    inv_id = _invite(client, keys["owner"], doc_id, "new").json()["invitation_id"]

    # 非受让人不能确认
    assert _confirm(client, keys["owner"], inv_id).status_code == 403
    assert _confirm(client, keys["w1"], inv_id).status_code == 403
    assert _confirm(client, keys["other"], 9999).status_code == 403

    r = _confirm(client, keys["new"], inv_id)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["status"] == "confirmed"
    assert data["current_owner"] == "new"
    assert data["previous_owner"] == "owner"
    assert data["document_status"] == "sealed"
    assert data["witnesses"] == ["w1", "w2", "w3"]
    assert data["old_open_request"] is None
    assert BODY not in r.text

    # 原封存人立即失去权限
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).status_code == 403
    assert client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])).status_code == 403
    assert str(doc_id) in client.get("/documents", headers=auth(keys["new"])).text
    assert str(doc_id) not in client.get("/documents", headers=auth(keys["owner"])).text
    # 见证人仍在名单、仍可访问（开封前无正文）
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["w1"])).json()
    assert got["witnesses"] == ["w1", "w2", "w3"] and "body" not in got
    # 新封存人可见详情但仍无正文
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["new"])).json()
    assert got["status"] == "sealed" and "body" not in got

    # 邀请不能二次确认
    assert _confirm(client, keys["new"], inv_id).status_code == 409


def test_confirm_invalidates_active_request_and_old_approvals(client):
    keys, doc_id, dg = _setup(client)
    inv_id = _invite(client, keys["owner"], doc_id, "new").json()["invitation_id"]
    req = _create_request(client, keys["owner"], doc_id)
    assert _approve(client, keys["w1"], req, dg).json()["approval_count"] == 1

    r = _confirm(client, keys["new"], inv_id)
    assert r.status_code == 200, r.text
    assert r.json()["old_open_request"] == {
        "request_id": req, "status": "invalidated", "approval_count": 0
    }

    # 资料仍封存；旧请求终态 invalidated、旧票已删
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["new"])).json()
    assert got["status"] == "sealed" and "body" not in got
    assert got["latest_open_request"]["status"] == "invalidated"
    assert got["latest_open_request"]["approval_count"] == 0

    # 旧请求不能再同意/撤销
    assert _approve(client, keys["w2"], req, dg).status_code == 409
    assert client.post(
        f"/open-requests/{req}/revoke", json={}, headers=auth(keys["new"])
    ).status_code == 409

    # 新封存人可重新申请开封，从 0 票开始
    req2 = _create_request(client, keys["new"], doc_id)
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["new"])).json()[
        "latest_open_request"]["approval_count"] == 0
    _approve(client, keys["w1"], req2, dg)
    r = _approve(client, keys["w2"], req2, dg)
    assert r.status_code == 200 and r.json()["status"] == "opened"
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["new"])).json()
    assert got["body"] == BODY
    # 开封见证只计新请求的两票
    assert [a["username"] for a in got["witness_approvals"]] == ["w1", "w2"]

    records = client.get(f"/documents/{doc_id}/audit", headers=auth(keys["new"])).json()["records"]
    actions = [r["action"] for r in records]
    assert actions.index("request_invalidated") < actions.index("handover_confirmed")
    assert actions.count("handover_confirmed") == 1
    # 确认转移后原封存人无权查看审计（上面的记录是新封存人取的）


def test_confirm_settles_past_deadline_request_as_expired(passive_client):
    """确认时旧 pending 请求已过截止时刻：按原规则 expired（而非 invalidated）。

    禁用后台扫描，确定性地让“确认临界区”完成过期判定。
    """
    client = passive_client
    keys, doc_id, dg = _setup(client)
    inv_id = _invite(client, keys["owner"], doc_id, "new").json()["invitation_id"]
    req = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "快到期", "deadline": _in_seconds(1)},
        headers=auth(keys["owner"]),
    ).json()["request_id"]
    _approve(client, keys["w1"], req, dg)
    time.sleep(1.15)

    r = _confirm(client, keys["new"], inv_id)
    assert r.status_code == 200, r.text
    assert r.json()["old_open_request"] == {
        "request_id": req, "status": "expired", "approval_count": 0
    }
    records = client.get(f"/documents/{doc_id}/audit", headers=auth(keys["new"])).json()["records"]
    actions = [r["action"] for r in records]
    assert actions.index("request_expired") < actions.index("handover_confirmed")


def test_confirm_waiting_request_invalidates_without_opening(client):
    """waiting（两票集齐待到点，时刻未到）期间确认交接：请求失效，资料不开启。"""
    keys, doc_id, dg = _setup(client)
    inv_id = _invite(client, keys["owner"], doc_id, "new").json()["invitation_id"]
    req = _create_request(client, keys["owner"], doc_id, deadline_h=2, earliest=3600)
    _approve(client, keys["w1"], req, dg)
    assert _approve(client, keys["w2"], req, dg).json()["status"] == "waiting"

    r = _confirm(client, keys["new"], inv_id)
    assert r.status_code == 200
    assert r.json()["old_open_request"]["status"] == "invalidated"
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["new"])).json()
    assert got["status"] == "sealed" and "body" not in got
    assert got["latest_open_request"]["status"] == "invalidated"


def test_confirm_rejected_when_document_opened_by_due_time(passive_client):
    """已到最早开封时刻且两票已齐：确认临界区先开封，交接随即 409，身份不变。"""
    client = passive_client
    keys, doc_id, dg = _setup(client)
    r = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_hours(1)},
        headers=auth(keys["owner"]),
    )
    inv_id = r.json()["invitation_id"]
    resp = client.post(
        f"/documents/{doc_id}/open-requests",
        json={"reason": "到点交接赛跑", "deadline": _in_hours(1),
              "earliest_open_at": _in_seconds(1)},
        headers=auth(keys["owner"]),
    ).json()
    req = resp["request_id"]
    _approve(client, keys["w1"], req, dg)
    _approve(client, keys["w2"], req, dg)
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()[
        "latest_open_request"]["status"] == "waiting"

    time.sleep(1.15)
    r = _confirm(client, keys["new"], inv_id)
    assert r.status_code == 409 and BODY not in r.text

    # 资料已开封（到点开封先落库），封存人未变
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["status"] == "opened" and got["body"] == BODY
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["new"])).status_code == 403
    assert _get_inv(client, keys["owner"], inv_id).json()["status"] == "expired"

    records = client.get(f"/documents/{doc_id}/audit", headers=auth(keys["owner"])).json()["records"]
    actions = [r["action"] for r in records]
    assert "handover_confirmed" not in actions
    assert actions[-1] == "handover_invitation_expired"


def test_invitation_expires_when_document_opened_elsewhere(client):
    """邀请待确认期间资料经正常两票开封：邀请随之 expired，不能确认。"""
    keys, doc_id, dg = _setup(client)
    inv_id = _invite(client, keys["owner"], doc_id, "new").json()["invitation_id"]
    req = _create_request(client, keys["owner"], doc_id)
    _approve(client, keys["w1"], req, dg)
    _approve(client, keys["w2"], req, dg)  # 立即开封

    assert _get_inv(client, keys["new"], inv_id).json()["status"] == "expired"
    assert _confirm(client, keys["new"], inv_id).status_code == 409
    assert _invite(client, keys["owner"], doc_id, "new").status_code == 409  # 已开封


def test_pending_assignee_cannot_become_witness(client):
    """邀请待确认期间，受让人不能被替换进见证人名单（否则会变成新封存人兼见证人）。"""
    keys, doc_id, _ = _setup(client)
    assert _invite(client, keys["owner"], doc_id, "new").status_code == 201
    r = client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": "w3", "new_witness": "new"},
        headers=auth(keys["owner"]),
    )
    assert r.status_code == 409 and BODY not in r.text
    # 名单未变，交接仍可正常完成
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["witnesses"] == ["w1", "w2", "w3"]
    inv_id = 1
    assert _confirm(client, keys["new"], inv_id).status_code == 200
    # 交接完成后（资料仍封存），新封存人仍不能把自己加成见证人
    r = client.post(
        f"/documents/{doc_id}/witness-replacements",
        json={"old_witness": "w3", "new_witness": "new"},
        headers=auth(keys["new"]),
    )
    assert r.status_code == 400


def test_handover_persists_across_restart(client):
    """冷读库：交接结果（owner / 请求终态 / 旧票删除 / 邀请状态）持久一致。"""
    import os
    import sqlite3

    keys, doc_id, dg = _setup(client)
    inv_id = _invite(client, keys["owner"], doc_id, "new").json()["invitation_id"]
    req = _create_request(client, keys["owner"], doc_id)
    _approve(client, keys["w1"], req, dg)
    assert _confirm(client, keys["new"], inv_id).status_code == 200

    db_path = os.environ["SEAL_DB_PATH"]
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    owner = conn.execute("SELECT owner_id FROM documents WHERE id=?", (doc_id,)).fetchone()[0]
    new_id = conn.execute("SELECT id FROM users WHERE username='new'").fetchone()[0]
    old_id = conn.execute("SELECT id FROM users WHERE username='owner'").fetchone()[0]
    assert owner == new_id and owner != old_id
    assert conn.execute(
        "SELECT status FROM open_requests WHERE id=?", (req,)
    ).fetchone()[0] == "invalidated"
    assert conn.execute(
        "SELECT COUNT(*) FROM approvals WHERE request_id=?", (req,)
    ).fetchone()[0] == 0
    assert conn.execute(
        "SELECT status FROM handover_invitations WHERE id=?", (inv_id,)
    ).fetchone()[0] == "confirmed"
    witnesses = [
        r[0] for r in conn.execute(
            """SELECT u.username FROM document_witnesses w JOIN users u ON u.id=w.user_id
               WHERE w.document_id=? ORDER BY w.position""", (doc_id,)
        ).fetchall()
    ]
    assert witnesses == ["w1", "w2", "w3"]
    conn.close()


# ---------------------------------------------------------------------------
# 并发：确认 vs 撤回 / 确认 vs 第二票同意 —— 真实 uvicorn + 线程，唯一终态
# ---------------------------------------------------------------------------


def _start_server(tmp_path, monkeypatch, db_name="concurrent-handover.db", sweep_seconds=60):
    import socket
    import threading

    import httpx
    import uvicorn

    from app.main import app

    monkeypatch.setenv("SEAL_DB_PATH", str(tmp_path / db_name))
    monkeypatch.setenv("SWEEP_INTERVAL_SECONDS", str(sweep_seconds))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    end = time.time() + 10
    while time.time() < end:
        try:
            if httpx.get(base + "/health", timeout=1).status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        raise AssertionError("server did not start")
    return server, thread, base


def test_concurrent_confirm_vs_revoke_single_outcome(tmp_path, monkeypatch):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import httpx

    server, thread, base = _start_server(tmp_path, monkeypatch, "cr-handover.db")
    try:
        with httpx.Client(timeout=10) as c:
            def reg(n):
                return c.post(base + "/register", json={"username": n}).json()["api_key"]

            owner, new = reg("h-owner"), reg("h-new")
            for n in ("h-w1", "h-w2", "h-w3"):
                reg(n)
            doc_id = c.post(
                base + "/documents", json={"body": "HANDOVER-CR", "witnesses": ["h-w1", "h-w2", "h-w3"]},
                headers={"X-API-Key": owner},
            ).json()["document_id"]
            deadline = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
            inv_id = c.post(
                f"{base}/documents/{doc_id}/handover-invitations",
                json={"to_username": "h-new", "confirm_deadline": deadline},
                headers={"X-API-Key": owner},
            ).json()["invitation_id"]

        barrier = threading.Barrier(2)

        def do_confirm():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(f"{base}/handover-invitations/{inv_id}/confirm",
                              headers={"X-API-Key": new}).status_code

        def do_revoke():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(f"{base}/handover-invitations/{inv_id}/revoke",
                              headers={"X-API-Key": owner}).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            cf_code, rv_code = list(pool.map(lambda f: f(), [do_confirm, do_revoke]))

        with httpx.Client(timeout=10) as c:
            h_owner = {"X-API-Key": owner}
            status = c.get(f"{base}/handover-invitations/{inv_id}", headers=h_owner).json()["status"]
            records = c.get(f"{base}/documents/{doc_id}/audit", headers=h_owner).json()
            if status == "confirmed":
                # 交接先提交：原封存人随即失去权限，其撤回被统一拒绝（403）
                assert cf_code == 200 and rv_code == 403
                assert c.get(f"{base}/documents/{doc_id}", headers=h_owner).status_code == 403
                got = c.get(f"{base}/documents/{doc_id}", headers={"X-API-Key": new}).json()
                assert got["status"] == "sealed" and "body" not in got
            else:
                assert status == "revoked"
                assert rv_code == 200 and cf_code == 409
                assert c.get(f"{base}/documents/{doc_id}", headers=h_owner).status_code == 200
                assert c.get(f"{base}/documents/{doc_id}",
                             headers={"X-API-Key": new}).status_code == 403
            if status == "confirmed":
                records = c.get(f"{base}/documents/{doc_id}/audit",
                                headers={"X-API-Key": new}).json()
            confirmed = [r for r in records["records"] if r["action"] == "handover_confirmed"]
            revoked = [r for r in records["records"] if r["action"] == "handover_revoked"]
            assert len(confirmed) + len(revoked) == 1
    finally:
        server.should_exit = True
        thread.join(timeout=5)


def test_concurrent_confirm_vs_second_approval_single_outcome(tmp_path, monkeypatch):
    import hashlib
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import httpx

    server, thread, base = _start_server(tmp_path, monkeypatch, "ca-handover.db")
    try:
        with httpx.Client(timeout=10) as c:
            def reg(n):
                return c.post(base + "/register", json={"username": n}).json()["api_key"]

            owner, new = reg("ha-owner"), reg("ha-new")
            w1, w2, w3 = reg("ha-w1"), reg("ha-w2"), reg("ha-w3")
            body = "HANDOVER-APPROVAL-RACE"
            dg = hashlib.sha256(body.encode()).hexdigest()
            doc_id = c.post(
                base + "/documents",
                json={"body": body, "witnesses": ["ha-w1", "ha-w2", "ha-w3"]},
                headers={"X-API-Key": owner},
            ).json()["document_id"]
            deadline = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat()
            inv_id = c.post(
                f"{base}/documents/{doc_id}/handover-invitations",
                json={"to_username": "ha-new", "confirm_deadline": deadline},
                headers={"X-API-Key": owner},
            ).json()["invitation_id"]
            req_id = c.post(
                f"{base}/documents/{doc_id}/open-requests",
                json={"reason": "赛跑", "deadline": deadline}, headers={"X-API-Key": owner},
            ).json()["request_id"]
            assert c.post(
                f"{base}/open-requests/{req_id}/approve", json={"digest": dg},
                headers={"X-API-Key": w1},
            ).status_code == 200

        barrier = threading.Barrier(2)

        def do_confirm():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(f"{base}/handover-invitations/{inv_id}/confirm",
                              headers={"X-API-Key": new}).status_code

        def do_approve():
            barrier.wait()
            with httpx.Client(timeout=10) as c:
                return c.post(f"{base}/open-requests/{req_id}/approve", json={"digest": dg},
                              headers={"X-API-Key": w2}).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            cf_code, ap_code = list(pool.map(lambda f: f(), [do_confirm, do_approve]))

        with httpx.Client(timeout=10) as c:
            doc_owner_code = c.get(f"{base}/documents/{doc_id}", headers={"X-API-Key": owner}).status_code
            doc_new_resp = c.get(f"{base}/documents/{doc_id}", headers={"X-API-Key": new})
            # 交接成功后审计归新封存人；开封成功后审计归原封存人
            if doc_owner_code == 403:
                records = c.get(f"{base}/documents/{doc_id}/audit",
                                headers={"X-API-Key": new}).json()["records"]
            else:
                records = c.get(f"{base}/documents/{doc_id}/audit",
                                headers={"X-API-Key": owner}).json()["records"]
            actions = [r["action"] for r in records]

            if "handover_confirmed" in actions:
                # 交接先提交：第二票（随后到达）必被拒；旧请求 invalidated、资料仍封存
                assert cf_code == 200 and ap_code == 409
                assert doc_owner_code == 403
                assert doc_new_resp.status_code == 200
                doc_new = doc_new_resp.json()
                assert doc_new["status"] == "sealed"
                assert "body" not in doc_new
                assert doc_new["latest_open_request"]["status"] == "invalidated"
                assert actions.count("opened") == 0
                assert actions.count("handover_confirmed") == 1
            else:
                # 第二票先提交并开封：交接必被拒，开封恰好一次，身份不变
                assert ap_code == 200 and cf_code == 409
                assert doc_owner_code == 200
                # 受让人始终是无关第三方：开封前后都无权查看（403），正文不泄露
                assert doc_new_resp.status_code == 403 and body not in doc_new_resp.text
                owner_view = c.get(f"{base}/documents/{doc_id}",
                                   headers={"X-API-Key": owner}).json()
                assert owner_view["status"] == "opened" and owner_view["body"] == body
                assert actions.count("opened") == 1
                assert "handover_confirmed" not in actions
    finally:
        server.should_exit = True
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# 截止判定以取得写锁后的实际时刻为准（等待写锁期间越过确认截止时刻）
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def held_write_lock():
    """在测试进程内占用同一数据库文件的写锁，模拟“请求已到达、等待写锁”窗口。

    占用期间发起的交接写请求会阻塞在 BEGIN IMMEDIATE；释放写锁后，被阻塞的
    请求必须以“取得写锁后的实际时刻”做截止判定，而不是用请求到达时刻。
    """
    conn = sqlite3.connect(os.environ["SEAL_DB_PATH"], timeout=30.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
    finally:
        conn.rollback()
        conn.close()


@pytest.fixture
def no_sweeper_handover(monkeypatch):
    """停用后台扫描器：确保越过截止时刻的逾期结算由被测请求自身取锁后完成。"""
    from app.main import ExpirySweeper

    monkeypatch.setattr(ExpirySweeper, "sweep_once", staticmethod(lambda: 0))
    time.sleep(0.2)  # 让进行中的扫描收尾（测试扫描间隔 0.05s）


def _audit_actions(client, key, doc_id):
    records = client.get(f"/documents/{doc_id}/audit", headers=auth(key)).json()["records"]
    return [(r["action"], r["at"]) for r in records]


def test_confirm_waiting_past_deadline_expires_without_transfer(client, no_sweeper_handover):
    """确认在截止前发起、取得写锁时截止已过：置 expired + 逾期审计，沿用 409，
    不转移封存人身份、不因交接失效旧开封请求、不发交接通知；处理时刻在截止后。"""
    keys, doc_id, dg = _setup(client)
    # 1.2s 截止；同时造一个进行中（未到期）的开封请求并投一票
    r = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_seconds(1.2)},
        headers=auth(keys["owner"]),
    )
    inv_id = r.json()["invitation_id"]
    req = _create_request(client, keys["owner"], doc_id, deadline_h=2)
    assert _approve(client, keys["w1"], req, dg).status_code == 200

    outcome = {}

    def late_confirm():
        resp = _confirm(client, keys["new"], inv_id)
        outcome["status"] = resp.status_code
        outcome["detail"] = resp.json().get("detail")

    with held_write_lock():
        t = threading.Thread(target=late_confirm)
        t.start()
        time.sleep(1.6)  # 确认等待写锁期间越过 1.2s 的确认截止时刻
    t.join(10)

    assert outcome["status"] == 409
    assert outcome["detail"] == "交接邀请已逾期，不能确认（请封存人重新邀请）"

    # 邀请终态 expired（而非 confirmed），resolved_at 是锁后实际时刻（晚于截止）
    got = _get_inv(client, keys["new"], inv_id).json()
    assert got["status"] == "expired"
    deadline = got["confirm_deadline"]
    assert got["resolved_at"] is not None and got["resolved_at"] >= deadline

    # 身份未转移：原封存人仍可访问，受让人仍 403
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).status_code == 200
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["new"])).status_code == 403

    # 旧开封请求仍是 pending、旧票保留（没有因交接而 invalidated）
    got = client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).json()
    assert got["latest_open_request"]["status"] == "pending"
    assert got["latest_open_request"]["approval_count"] == 1

    # 审计：恰好一条逾期记录、无交接确认/请求失效；逾期审计时刻不早于截止
    actions = _audit_actions(client, keys["owner"], doc_id)
    assert [a for a, _ in actions].count("handover_invitation_expired") == 1
    assert "handover_confirmed" not in [a for a, _ in actions]
    assert "request_invalidated" not in [a for a, _ in actions]
    expired_at = next(at for a, at in actions if a == "handover_invitation_expired")
    assert expired_at >= deadline

    # 没有交接通知投递给任何人
    for name in ("owner", "new", "w1", "w2", "w3"):
        notes = client.get("/notifications", headers=auth(keys[name])).json()["notifications"]
        assert all(n["event_type"] != "handover_confirmed" for n in notes)

    # 错误体不泄露正文
    assert BODY not in outcome.get("detail", "")


def test_revoke_waiting_past_deadline_expires_instead_of_revoked(client, no_sweeper_handover):
    """撤回在截止前发起、取得写锁时截止已过：邀请置 expired + 逾期审计，沿用
    409，绝不能改成 revoked；处理时刻反映实际结算时刻（晚于截止）。"""
    keys, doc_id, _ = _setup(client)
    inv_id = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_seconds(1.2)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]

    outcome = {}

    def late_revoke():
        resp = _revoke(client, keys["owner"], inv_id)
        outcome["status"] = resp.status_code
        outcome["detail"] = resp.json().get("detail")

    with held_write_lock():
        t = threading.Thread(target=late_revoke)
        t.start()
        time.sleep(1.6)  # 撤回等待写锁期间越过 1.2s 的确认截止时刻
    t.join(10)

    assert outcome["status"] == 409
    assert outcome["detail"] == "交接邀请已逾期，不能撤回（可重新邀请）"

    got = _get_inv(client, keys["owner"], inv_id).json()
    assert got["status"] == "expired" and got["resolved_at"] >= got["confirm_deadline"]

    actions = _audit_actions(client, keys["owner"], doc_id)
    assert [a for a, _ in actions].count("handover_invitation_expired") == 1
    assert "handover_revoked" not in [a for a, _ in actions]

    # 逾期后可重新邀请（原规则不变）
    assert _invite(client, keys["owner"], doc_id, "new").status_code == 201


def test_confirm_lock_acquired_before_deadline_still_confirms(client, no_sweeper_handover):
    """截止前取得写锁的确认仍按原规则完成；完成时刻不早于写锁释放时刻。"""
    keys, doc_id, _ = _setup(client)
    inv_id = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_seconds(5)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]

    outcome = {}

    def do_confirm():
        resp = _confirm(client, keys["new"], inv_id)
        outcome["status"] = resp.status_code
        outcome["json"] = resp.json() if resp.status_code == 200 else None

    with held_write_lock():
        t = threading.Thread(target=do_confirm)
        t.start()
        time.sleep(0.5)  # 写锁在截止前释放，确认取锁时截止未到
        release_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds")
    t.join(10)

    assert outcome["status"] == 200
    data = outcome["json"]
    assert data["status"] == "confirmed" and data["current_owner"] == "new"
    assert data["resolved_at"] >= release_at
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).status_code == 403
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["new"])).status_code == 200


def test_past_deadline_confirm_with_invalid_key_gets_401_without_settling(
    client, no_sweeper_handover
):
    """持失效密钥在截止后确认：写锁内复核先返回既有 401，整体回滚——
    不触发逾期结算（邀请仍 pending、无逾期审计）、不转移身份，也不泄露正文。

    authed_write_tx 在任何业务检查与到点结算之前复核密钥：即便确认截止时刻
    已过（模拟请求在写锁队列中等待期间被并发轮换作废），失效密钥仍先得到
    401，逾期结算只能由随后的合法请求/扫描器完成。
    """
    keys, doc_id, _ = _setup(client)
    inv_id = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_seconds(1.0)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]
    old_new_key = keys["new"]
    # 受让人在截止前轮换密钥，旧密钥作废
    keys["new"] = client.post(
        "/me/api-key/rotate", headers=auth(old_new_key)
    ).json()["api_key"]
    time.sleep(1.2)  # 确认截止时刻已过；扫描器已停用

    # 持旧密钥确认：既有 401 优先，错误体不泄露正文
    r = _confirm(client, old_new_key, inv_id)
    assert r.status_code == 401 and r.json()["detail"] == "凭据无效"
    assert BODY not in r.text

    # 401 整体回滚：邀请仍 pending、没有逾期审计，身份从未转移
    assert _get_inv(client, keys["owner"], inv_id).json()["status"] == "pending"
    actions = _audit_actions(client, keys["owner"], doc_id)
    assert "handover_invitation_expired" not in [a for a, _ in actions]
    assert "handover_confirmed" not in [a for a, _ in actions]
    assert client.get(f"/documents/{doc_id}", headers=auth(keys["owner"])).status_code == 200

    # 新密钥合法请求在锁后按实际时刻结算：逾期拒绝、置 expired
    assert _confirm(client, keys["new"], inv_id).status_code == 409
    assert _get_inv(client, keys["new"], inv_id).json()["status"] == "expired"

    # 不存在的/无法识别的密钥同样 401（不区分账号是否存在）
    assert _confirm(client, "deadbeef", inv_id).status_code == 401


def test_waiting_confirm_non_assignee_still_403(client, no_sweeper_handover):
    """等待写锁越过截止的非受让人确认：仍沿用既有 403，不泄露正文/存在性。"""
    keys, doc_id, _ = _setup(client)
    inv_id = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_seconds(1.2)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]

    outcome = {}

    def late_confirm():
        resp = _confirm(client, keys["other"], inv_id)
        outcome["status"] = resp.status_code
        outcome["detail"] = resp.json().get("detail")

    with held_write_lock():
        t = threading.Thread(target=late_confirm)
        t.start()
        time.sleep(1.6)
    t.join(10)

    assert outcome["status"] == 403
    assert outcome["detail"] == "只有受让人本人可以确认交接"
    assert BODY not in outcome.get("detail", "")


def test_waiting_revoke_concurrent_with_sweeper_single_terminal_state(client):
    """撤回排队越期与到期扫描并发：扫描器与撤回事务共用写锁，邀请只有一个终态。

    无论扫描器先提交还是撤回取锁后自行结算，邀请必为 expired（不会出现
    revoked 与 expired 两个终态，也不会重复逾期审计）。
    """
    keys, doc_id, _ = _setup(client)
    inv_id = client.post(
        f"/documents/{doc_id}/handover-invitations",
        json={"to_username": "new", "confirm_deadline": _in_seconds(1.2)},
        headers=auth(keys["owner"]),
    ).json()["invitation_id"]

    revoke_code = {}

    def late_revoke():
        resp = _revoke(client, keys["owner"], inv_id)
        revoke_code["status"] = resp.status_code

    from app.main import ExpirySweeper

    with held_write_lock():
        t = threading.Thread(target=late_revoke)
        t.start()
        time.sleep(1.6)  # 撤回已排队且截止已过；写锁释放后扫描器可能抢先
    t.join(10)
    # 写锁刚释放：立刻允许扫描器与排队撤回竞争，再补一轮扫描兜底
    time.sleep(0.3)
    ExpirySweeper.sweep_once()

    assert revoke_code["status"] == 409
    got = _get_inv(client, keys["owner"], inv_id).json()
    assert got["status"] == "expired"
    actions = _audit_actions(client, keys["owner"], doc_id)
    assert [a for a, _ in actions].count("handover_invitation_expired") == 1
    assert "handover_revoked" not in [a for a, _ in actions]
