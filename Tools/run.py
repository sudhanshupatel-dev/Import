"""
MobiScan - Start the OWASP MASTG Scanner
Run this script to start the web server
"""
import sys
import os

# Ensure we're in the right directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("MOBISCAN_HOST", "0.0.0.0")
    port = int(os.environ.get("MOBISCAN_PORT", "8000"))

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    🔍 MobiScan - OWASP MASTG Mobile Security Scanner      ║
║                                                              ║
║    Starting on: http://{host}:{port}                           ║
║                                                              ║
║    Features:                                                 ║
║    • OWASP MASTG Static Analysis (Android & iOS)            ║
║    • Auto-generated Frida Scripts                            ║
║    • App Version Comparison                                  ║
║    • Activity/Screen Diff Analysis                           ║
║    • PSS ID & Test Owner Tracking                            ║
║                                                              ║
║    Platforms from your network can access this at:           ║
║    http://<YOUR-IP>:{port}                                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")

    uvicorn.run(
        "app:app",
        host=host,
        port=port,
        reload=False,
        log_level="info",
    )
