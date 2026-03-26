#!/bin/bash
# Run this script to verify all fixes work correctly

echo "======================================================================"
echo "PHISHING DETECTION SYSTEM - FIX VERIFICATION"
echo "======================================================================"
echo ""

echo "Step 1: Checking Python files syntax..."
python -m py_compile model.py && echo "✅ model.py syntax OK" || echo "❌ model.py has syntax errors"
python -m py_compile utils.py && echo "✅ utils.py syntax OK" || echo "❌ utils.py has syntax errors"
python -m py_compile app.py && echo "✅ app.py syntax OK" || echo "❌ app.py has syntax errors"

echo ""
echo "Step 2: Training the model (if not already trained)..."
if [ ! -f "phishing_model.pkl" ]; then
    echo "Model file not found. Training..."
    python main.py
else
    echo "✅ Model file already exists"
fi

echo ""
echo "Step 3: Running robustness tests..."
python test_robustness.py

echo ""
echo "Step 4: Ready to run Streamlit UI!"
echo "Run: streamlit run app.py"
echo ""
echo "======================================================================"
