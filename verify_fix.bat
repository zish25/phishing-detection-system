@echo off
REM Windows batch script to verify all fixes work correctly

echo ======================================================================
echo PHISHING DETECTION SYSTEM - FIX VERIFICATION ^(Windows^)
echo ======================================================================
echo.

echo Step 1: Checking Python files syntax...
python -m py_compile model.py >nul 2>&1 && echo [OK] model.py syntax correct || echo [ERROR] model.py has syntax errors
python -m py_compile utils.py >nul 2>&1 && echo [OK] utils.py syntax correct || echo [ERROR] utils.py has syntax errors
python -m py_compile app.py >nul 2>&1 && echo [OK] app.py syntax correct || echo [ERROR] app.py has syntax errors

echo.
echo Step 2: Checking if model is trained...
if exist "phishing_model.pkl" (
    echo [OK] Model file exists
) else (
    echo [INFO] Model file not found. You need to train it first.
    echo [INFO] Run: python main.py
)

echo.
echo Step 3: Running robustness tests...
python test_robustness.py

echo.
echo Step 4: System is ready!
echo To run the Streamlit UI:
echo   streamlit run app.py
echo.
echo ======================================================================
pause
