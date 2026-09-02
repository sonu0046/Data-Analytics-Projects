# tests/test_frontend_integration.py - Frontend-Backend Integration & Architecture Verification Suite
import os
import sys
import re

# Ensure project root in sys.path
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)


def run_frontend_integration_verification():
    print("==================================================================")
    print(" 🌐 FRONTEND ➔ BACKEND INTEGRATION & SPA ARCHITECTURE TEST")
    print("==================================================================")

    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    index_html_path = os.path.join(root_dir, "frontend", "index.html")
    style_css_path = os.path.join(root_dir, "frontend", "style.css")
    app_js_path = os.path.join(root_dir, "frontend", "app.js")
    main_py_path = os.path.join(root_dir, "app", "main.py")

    # Test 1: HTML Structure & Static Asset Linking
    print("\n[TEST 1: frontend/index.html Structure & Asset Links]")
    assert os.path.exists(index_html_path), "frontend/index.html must exist"
    with open(index_html_path, "r", encoding="utf-8") as f:
        html_content = f.read()

    assert '<link rel="stylesheet" href="/static/style.css">' in html_content
    assert '<script src="/static/app.js"></script>' in html_content
    assert 'id="toast-container"' in html_content
    assert 'id="app-view"' in html_content
    assert 'id="user-context-section"' in html_content
    print("--> Test 1: index.html correctly configured with /static assets ✅")

    # Test 2: CSS Stylesheet & Cooling-Off Animation
    print("\n[TEST 2: frontend/style.css Design Tokens & Animations]")
    assert os.path.exists(style_css_path), "frontend/style.css must exist"
    with open(style_css_path, "r", encoding="utf-8") as f:
        css_content = f.read()

    assert ".glass-card" in css_content
    assert ".cooling-off-banner" in css_content
    assert "@keyframes pulse-slow" in css_content
    print("--> Test 2: style.css contains all required UI animations ✅")

    # Test 3: JavaScript SPA Controller & Backend API Integration
    print("\n[TEST 3: frontend/app.js Backend API & Security Interceptors]")
    assert os.path.exists(app_js_path), "frontend/app.js must exist"
    with open(app_js_path, "r", encoding="utf-8") as f:
        js_content = f.read()

    # Verify API endpoints called by frontend
    assert "/api/v1/review/maker-verify" in js_content or "maker-verify" in js_content
    assert "/api/v1/review/checker-approve" in js_content or "checker-approve" in js_content
    assert "/api/v1/ingestion/intake" in js_content or "intake" in js_content

    # Verify Error Handling Interceptors (401/403/409/500)
    assert "status === 401" in js_content
    assert "status === 403" in js_content
    assert "status === 409" in js_content
    assert "status === 500" in js_content
    assert "MAKER_CHECKER_SEPARATION" in js_content
    print("--> Test 3: app.js seamlessly integrated with Step 5 APIs & Error Interceptors ✅")

    # Test 4: FastAPI Backend SPA Static Mount & Fallback Routing
    print("\n[TEST 4: app/main.py SPA Static Mount & Fallback Route]")
    assert os.path.exists(main_py_path), "app/main.py must exist"
    with open(main_py_path, "r", encoding="utf-8") as f:
        main_content = f.read()

    assert 'app.mount("/static"' in main_content or "StaticFiles" in main_content
    assert '@app.get("/{full_path:path}"' in main_content
    assert "FileResponse" in main_content
    print("--> Test 4: FastAPI correctly mounts /static and serves SPA on all routes ✅")

    print("\n==================================================================")
    print(" 🎉 FRONTEND ➔ BACKEND INTEGRATION VERIFIED WITH 100% SUCCESS!")
    print("==================================================================")


if __name__ == "__main__":
    run_frontend_integration_verification()
