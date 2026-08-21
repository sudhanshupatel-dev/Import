"""
Database models for scan results and comparisons
"""
import os
import json
from datetime import datetime
from peewee import (
    SqliteDatabase, Model, CharField, TextField,
    DateTimeField, IntegerField, ForeignKeyField,
    FloatField, BooleanField
)

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                       "uploads", "codehunter.db")
db = SqliteDatabase(DB_PATH, pragmas={"journal_mode": "wal"})


class BaseModel(Model):
    class Meta:
        database = db


class Scan(BaseModel):
    """Individual scan result."""
    pss_id = CharField(index=True)
    test_owner = CharField()
    scan_date = DateTimeField(default=datetime.now)
    app_name = CharField(default="")
    package_name = CharField(default="", index=True)
    platform = CharField(default="Android")  # Android or iOS
    version = CharField(default="")
    file_name = CharField()
    file_size = IntegerField(default=0)
    file_hash = CharField(default="")
    risk_score = IntegerField(default=0)
    risk_level = CharField(default="Info")
    critical_count = IntegerField(default=0)
    high_count = IntegerField(default=0)
    medium_count = IntegerField(default=0)
    low_count = IntegerField(default=0)
    info_count = IntegerField(default=0)
    pass_count = IntegerField(default=0)
    fail_count = IntegerField(default=0)
    warning_count = IntegerField(default=0)
    scan_results = TextField(default="{}")  # JSON
    frida_script = TextField(default="")
    detections = TextField(default="{}")  # JSON
    status = CharField(default="completed")  # running, completed, error
    error_message = TextField(default="")
    notes = TextField(default="")


class Comparison(BaseModel):
    """Comparison between two scans of same app (different versions)."""
    name = CharField()
    created_date = DateTimeField(default=datetime.now)
    scan_a = ForeignKeyField(Scan, backref="comparisons_as_a")
    scan_b = ForeignKeyField(Scan, backref="comparisons_as_b")
    comparison_results = TextField(default="{}")  # JSON
    activity_diff = TextField(default="{}")  # JSON


def init_db():
    """Initialize database tables."""
    db.connect(reuse_if_open=True)
    db.create_tables([Scan, Comparison])


def save_scan(pss_id, test_owner, app_name, package_name, platform, version,
              file_name, file_size, file_hash, report, frida_script=""):
    """Save a scan result to the database."""
    severity = report.get("severity_counts", {})
    status = report.get("status_counts", {})

    scan = Scan.create(
        pss_id=pss_id,
        test_owner=test_owner,
        app_name=app_name,
        package_name=package_name,
        platform=platform,
        version=version,
        file_name=file_name,
        file_size=file_size,
        file_hash=file_hash,
        risk_score=report.get("risk_score", 0),
        risk_level=report.get("risk_level", "Info"),
        critical_count=severity.get("Critical", 0),
        high_count=severity.get("High", 0),
        medium_count=severity.get("Medium", 0),
        low_count=severity.get("Low", 0),
        info_count=severity.get("Info", 0),
        pass_count=status.get("PASS", 0),
        fail_count=status.get("FAIL", 0),
        warning_count=status.get("WARNING", 0),
        scan_results=json.dumps(report),
        frida_script=frida_script,
        detections=json.dumps(report.get("detections", {})),
        status="completed",
    )
    return scan


def get_scans_by_package(package_name):
    """Get all scans for a specific package name."""
    return (Scan.select()
            .where(Scan.package_name == package_name)
            .order_by(Scan.scan_date.desc()))


def get_all_scans():
    """Get all scans."""
    return Scan.select().order_by(Scan.scan_date.desc())


def get_scan_by_id(scan_id):
    """Get a scan by ID."""
    return Scan.get_or_none(Scan.id == scan_id)


def get_all_package_groups():
    """Get scans grouped by package name."""
    scans = Scan.select().order_by(Scan.package_name, Scan.scan_date.desc())
    groups = {}
    for scan in scans:
        pkg = scan.package_name or "Unknown"
        if pkg not in groups:
            groups[pkg] = []
        groups[pkg].append(scan)
    return groups
