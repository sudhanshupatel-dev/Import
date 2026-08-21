"""
MobiScan - OWASP MASTG Mobile Security Scanner
A pentesting tool for Android and iOS applications
"""
import os
import json
import shutil
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from core.scanner.apk_scanner import ApkScanner
from core.scanner.ios_scanner import IosScanner
from core.frida.generator import FridaScriptGenerator
from core.comparison import AppComparator
from core.utils.database import (
    init_db, save_scan, get_all_scans, get_scan_by_id,
    get_scans_by_package, get_all_package_groups, Scan
)

# ─── App Setup ────────────────────────────────────────────────────────

BASE_DIR = Path(__file__).parent
UPLOAD_DIR = BASE_DIR / "uploads" / "scans"
SCAN_DIR = BASE_DIR / "uploads" / "scans"
COMPARE_DIR = BASE_DIR / "uploads" / "comparisons"

for d in [UPLOAD_DIR, SCAN_DIR, COMPARE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="MobiScan",
    description="OWASP MASTG Mobile Application Security Testing Scanner",
    version="1.0.0"
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Initialize database
init_db()


# ─── Helper Functions ─────────────────────────────────────────────────

def get_platform_from_filename(filename: str) -> str:
    """Detect platform from file extension."""
    ext = Path(filename).suffix.lower()
    if ext == ".apk":
        return "Android"
    elif ext == ".ipa":
        return "iOS"
    elif ext == ".aab":
        return "Android"
    return "Unknown"


def format_file_size(size_bytes: int) -> str:
    """Format file size to human readable."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ─── Page Routes ──────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Dashboard / Home page."""
    scans = get_all_scans()
    scan_list = []
    for s in scans[:50]:
        scan_list.append({
            "id": s.id,
            "pss_id": s.pss_id,
            "test_owner": s.test_owner,
            "scan_date": s.scan_date.strftime("%Y-%m-%d %H:%M") if s.scan_date else "",
            "app_name": s.app_name,
            "package_name": s.package_name,
            "platform": s.platform,
            "version": s.version,
            "risk_level": s.risk_level,
            "risk_score": s.risk_score,
            "critical_count": s.critical_count,
            "high_count": s.high_count,
            "medium_count": s.medium_count,
            "low_count": s.low_count,
            "fail_count": s.fail_count,
            "warning_count": s.warning_count,
            "pass_count": s.pass_count,
            "file_size": format_file_size(s.file_size) if s.file_size else "N/A",
        })

    # Stats
    total_scans = len(scan_list)
    total_critical = sum(s["critical_count"] for s in scan_list)
    total_high = sum(s["high_count"] for s in scan_list)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "scans": scan_list,
            "total_scans": total_scans,
            "total_critical": total_critical,
            "total_high": total_high,
        },
    )


@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    """Upload page."""
    return templates.TemplateResponse(request, "upload.html")


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: int):
    """Scan detail / report page."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    results = json.loads(scan.scan_results) if scan.scan_results else {}
    frida_script = scan.frida_script or ""
    detections = json.loads(scan.detections) if scan.detections else {}

    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        {
            "scan": scan,
            "results": results,
            "frida_script": frida_script,
            "detections": detections,
            "format_file_size": format_file_size,
        },
    )


@app.get("/compare", response_class=HTMLResponse)
async def compare_page(request: Request):
    """App comparison page - shows all apps with multiple versions."""
    groups = get_all_package_groups()
    group_data = []
    for pkg, scans in groups.items():
        if len(scans) >= 1:
            group_data.append({
                "package_name": pkg,
                "app_name": scans[0].app_name or pkg,
                "platform": scans[0].platform,
                "scan_count": len(scans),
                "scans": [{
                    "id": s.id,
                    "version": s.version,
                    "scan_date": s.scan_date.strftime("%Y-%m-%d %H:%M") if s.scan_date else "",
                    "risk_level": s.risk_level,
                    "risk_score": s.risk_score,
                    "test_owner": s.test_owner,
                } for s in scans]
            })

    return templates.TemplateResponse(
        request,
        "compare.html",
        {
            "groups": group_data,
        },
    )


@app.get("/compare/{scan_a_id}/{scan_b_id}", response_class=HTMLResponse)
async def compare_detail(request: Request, scan_a_id: int, scan_b_id: int):
    """Compare two specific scan results."""
    scan_a = get_scan_by_id(scan_a_id)
    scan_b = get_scan_by_id(scan_b_id)
    if not scan_a or not scan_b:
        raise HTTPException(status_code=404, detail="Scan(s) not found")

    report_a = json.loads(scan_a.scan_results) if scan_a.scan_results else {}
    report_b = json.loads(scan_b.scan_results) if scan_b.scan_results else {}

    comparator = AppComparator()
    comparison = comparator.compare(report_a, report_b)
    activity_diff = comparator.compare_activities(report_a, report_b)

    return templates.TemplateResponse(
        request,
        "compare_detail.html",
        {
            "scan_a": scan_a,
            "scan_b": scan_b,
            "comparison": comparison,
            "activity_diff": activity_diff,
        },
    )


@app.get("/frida-scripts", response_class=HTMLResponse)
async def frida_scripts_page(request: Request):
    """Frida scripts library page."""
    scripts = FridaScriptGenerator.get_all_scripts()
    return templates.TemplateResponse(
        request,
        "frida_scripts.html",
        {
            "scripts": scripts,
        },
    )


@app.get("/dynamic", response_class=HTMLResponse)
async def dynamic_page(request: Request):
    """Dynamic Analysis standalone page."""
    scans = get_all_scans()
    scan_list = []
    for s in scans[:20]:
        scan_list.append({
            "id": s.id,
            "pss_id": s.pss_id,
            "app_name": s.app_name,
            "package_name": s.package_name,
            "platform": s.platform,
            "version": s.version,
        })
    return templates.TemplateResponse(
        request,
        "dynamic.html",
        {"scans": scan_list},
    )


@app.get("/mastg-tests", response_class=HTMLResponse)
async def mastg_tests_page(request: Request):
    """OWASP MASTG tests reference page."""
    from core.rules.mastg_tests import get_all_tests, get_android_tests, get_ios_tests
    all_tests = get_all_tests()
    android_tests = get_android_tests()
    ios_tests = get_ios_tests()

    return templates.TemplateResponse(
        request,
        "mastg_tests.html",
        {
            "all_tests": all_tests,
            "android_tests": android_tests,
            "ios_tests": ios_tests,
        },
    )


# ─── API Routes ───────────────────────────────────────────────────────

@app.post("/api/upload-and-scan")
async def upload_and_scan(
    file: UploadFile = File(...),
    pss_id: str = Form(...),
    test_owner: str = Form(...),
):
    """Upload APK/IPA and perform OWASP MASTG scan."""
    # Validate PSS ID
    if not pss_id.startswith("PSS-") or not pss_id[4:].isdigit():
        raise HTTPException(status_code=400, detail="PSS ID must be in format PSS-XXXX (e.g., PSS-1234)")

    platform = get_platform_from_filename(file.filename)
    if platform == "Unknown":
        raise HTTPException(status_code=400, detail="Unsupported file type. Please upload .apk or .ipa file.")

    # Save uploaded file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_filename = f"{pss_id}_{timestamp}_{file.filename}"
    file_path = UPLOAD_DIR / safe_filename

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    file_size = os.path.getsize(file_path)
    file_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()

    try:
        # Perform scan
        if platform == "Android":
            scanner = ApkScanner()
        else:
            scanner = IosScanner()

        report = scanner.scan(str(file_path))

        if "error" in report:
            raise Exception(report["error"])

        # Generate Frida scripts
        detections = report.get("detections", {})
        if platform == "Android":
            frida_script = FridaScriptGenerator.generate_for_android(detections)
        else:
            frida_script = FridaScriptGenerator.generate_for_ios(detections)

        # Extract app info
        file_info = report.get("file_info", {})
        app_name = file_info.get("app_name", file.filename)
        package_name = file_info.get("package_name", file_info.get("bundle_id", "Unknown"))
        version = file_info.get("version_name", file_info.get("version", "Unknown"))

        # Save to database
        scan = save_scan(
            pss_id=pss_id,
            test_owner=test_owner,
            app_name=app_name,
            package_name=package_name,
            platform=platform,
            version=version,
            file_name=file.filename,
            file_size=file_size,
            file_hash=file_hash,
            report=report,
            frida_script=frida_script,
        )

        return JSONResponse({
            "success": True,
            "scan_id": scan.id,
            "redirect": f"/scan/{scan.id}",
            "summary": {
                "platform": platform,
                "app_name": app_name,
                "package_name": package_name,
                "version": version,
                "risk_score": report.get("risk_score", 0),
                "risk_level": report.get("risk_level", "Info"),
                "severity_counts": report.get("severity_counts", {}),
                "total_tests": report.get("total_tests", 0),
            }
        })

    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": str(e)
        }, status_code=500)


@app.get("/api/scans")
async def api_get_scans():
    """Get all scans."""
    scans = get_all_scans()
    return [{
        "id": s.id,
        "pss_id": s.pss_id,
        "test_owner": s.test_owner,
        "scan_date": s.scan_date.isoformat() if s.scan_date else None,
        "app_name": s.app_name,
        "package_name": s.package_name,
        "platform": s.platform,
        "version": s.version,
        "risk_score": s.risk_score,
        "risk_level": s.risk_level,
    } for s in scans]


@app.get("/api/scan/{scan_id}/report")
async def api_get_report(scan_id: int):
    """Get full scan report."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return json.loads(scan.scan_results) if scan.scan_results else {}


@app.get("/api/scan/{scan_id}/frida")
async def api_get_frida_script(scan_id: int):
    """Get generated Frida script."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return Response(content=scan.frida_script, media_type="text/plain")


@app.get("/api/packages")
async def api_get_packages():
    """Get all packages with scan counts."""
    groups = get_all_package_groups()
    return [{
        "package_name": pkg,
        "app_name": scans[0].app_name,
        "platform": scans[0].platform,
        "scan_count": len(scans),
        "latest_scan": scans[0].scan_date.isoformat() if scans[0].scan_date else None,
    } for pkg, scans in groups.items()]


@app.get("/api/compare/{scan_a_id}/{scan_b_id}")
async def api_compare(scan_a_id: int, scan_b_id: int):
    """Compare two scans."""
    scan_a = get_scan_by_id(scan_a_id)
    scan_b = get_scan_by_id(scan_b_id)
    if not scan_a or not scan_b:
        raise HTTPException(status_code=404, detail="Scan(s) not found")

    report_a = json.loads(scan_a.scan_results) if scan_a.scan_results else {}
    report_b = json.loads(scan_b.scan_results) if scan_b.scan_results else {}

    comparator = AppComparator()
    return comparator.compare(report_a, report_b)


@app.delete("/api/scan/{scan_id}")
async def api_delete_scan(scan_id: int):
    """Delete a scan."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan.delete_instance()
    return {"success": True}


# ─── Dynamic Analysis API ──────────────────────────────────────────────

def run_adb(args: list, serial: str = None) -> dict:
    """Run an ADB command and return output."""
    import subprocess
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"stdout": result.stdout.strip(), "stderr": result.stderr.strip(), "returncode": result.returncode}
    except FileNotFoundError:
        return {"stdout": "", "stderr": "ADB not found. Install Android SDK platform-tools.", "returncode": -1}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "ADB command timed out", "returncode": -1}


def run_frida_script(serial: str, package: str, script: str, timeout: int = 15) -> dict:
    """Run a Frida script on a device."""
    import subprocess
    import tempfile
    import os

    # Write script to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(script)
        script_path = f.name

    try:
        cmd = ["frida", "-U", "-s", serial, "-l", script_path, "-n", package]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"success": result.returncode == 0, "output": result.stdout + result.stderr}
    except FileNotFoundError:
        return {"success": False, "error": "Frida not found. Install: pip install frida-tools"}
    except subprocess.TimeoutExpired:
        return {"success": True, "output": "Script attached (timed out as expected - test completed)"}
    except Exception as e:
        return {"success": False, "error": str(e)}
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass


@app.get("/api/dynamic/detect-devices")
async def detect_devices():
    """Detect connected Android devices via ADB."""
    result = run_adb(["devices", "-l"])
    devices = []
    if result["returncode"] == 0:
        for line in result["stdout"].splitlines()[1:]:
            if not line.strip() or "offline" in line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                model = "Unknown"
                android_ver = "Unknown"
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.split(":")[1]
                    if p.startswith("transport_id:"):
                        pass

                # Get Android version
                ver_result = run_adb(["shell", "getprop", "ro.build.version.release"], serial)
                if ver_result["returncode"] == 0 and ver_result["stdout"]:
                    android_ver = ver_result["stdout"]

                devices.append({
                    "serial": serial,
                    "model": model,
                    "android_version": android_ver,
                    "status": "device"
                })

    return {"devices": devices}


@app.post("/api/dynamic/connect")
async def connect_device(request: Request):
    """Connect to a device and verify package is installed."""
    body = await request.json()
    serial = body.get("serial")
    package = body.get("package")

    if not serial:
        return {"success": False, "error": "No serial provided"}

    # Verify device is reachable
    result = run_adb(["get-state"], serial)
    if result["returncode"] != 0:
        return {"success": False, "error": f"Device not reachable: {result['stderr']}"}

    # If package is Unknown, try to find running app
    if package == "Unknown" or not package:
        result = run_adb(["shell", "dumpsys", "activity", "recents"], serial)
        if result["returncode"] == 0:
            # Try to extract package from recent activities
            import re
            match = re.search(r'([a-zA-Z][a-zA-Z0-9_.]+/[a-zA-Z0-9_.]+)', result["stdout"])
            if match:
                package = match.group(1).split("/")[0]

    return {"success": True, "serial": serial, "package": package or "Unknown"}


@app.post("/api/dynamic/run-test")
async def run_dynamic_test(request: Request):
    """Run a dynamic analysis test."""
    body = await request.json()
    serial = body.get("serial")
    package = body.get("package")
    test_name = body.get("test")
    script = body.get("script")

    if not serial or not script:
        return {"success": False, "error": "Missing serial or script"}

    # Run the Frida script
    result = run_frida_script(serial, package, script)
    return result


# ─── Run ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
