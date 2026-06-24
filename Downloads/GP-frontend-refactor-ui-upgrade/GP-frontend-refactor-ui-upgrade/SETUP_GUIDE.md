# Quick Start Guide

## First Time Setup

### Step 1: Install Node.js
1. Go to https://nodejs.org/
2. Download LTS version (recommended)
3. Run installer and follow prompts
4. Verify: Open PowerShell and run `node --version`

### Step 2: Install Python
1. Go to https://www.python.org/downloads/
2. Download Python 3.10+ 
3. **IMPORTANT**: Check "Add Python to PATH" during installation
4. Verify: Open PowerShell and run `python --version`

### Step 3: Install Ollama
1. Go to https://ollama.ai/
2. Download Ollama for Windows
3. Run installer
4. Ollama will start automatically
5. Verify: Open PowerShell and run `ollama --version`

### Step 4: Download Mistral Model
```powershell
# In PowerShell
ollama pull mistral:latest
```
This will download the Mistral AI model (about 4GB). Wait for it to complete.

### Step 5: Install Frontend Dependencies
```powershell
# Navigate to project
cd C:\Users\MARIAM\agent-security-tester

# Install Node modules
npm install
```

### Step 6: Install Backend Dependencies
```powershell
# Navigate to backend
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\activate

# Install Python packages
pip install -r requirements.txt
```

## Running the Application

### Terminal 1: Start Frontend
```powershell
cd C:\Users\MARIAM\agent-security-tester
npm run dev
```
✅ Frontend running at: http://localhost:3000

### Terminal 2: Start Backend
```powershell
cd C:\Users\MARIAM\agent-security-tester\backend
.\venv\Scripts\activate
python main.py
```
✅ Backend running at: http://localhost:8000

### Open in Browser
Navigate to: **http://localhost:3000**

## Testing the Application

1. Click **"Load Example"** button
2. Review the sample agent description
3. Click **"Start Security Analysis"**
4. Wait 10-30 seconds for analysis
5. View the vulnerability report
6. Click **"Export JSON"** to download results

## Common Issues & Solutions

### "node is not recognized"
- Restart PowerShell after installing Node.js
- Or add Node.js to PATH manually

### "python is not recognized"
- Reinstall Python with "Add to PATH" checked
- Or add Python to PATH manually

### "ollama: command not found"
- Restart computer after installing Ollama
- Check if Ollama service is running

### Port 3000 already in use
```powershell
# Use different port
npm run dev -- -p 3001
```

### Backend connection error
- Make sure Ollama is running
- Verify Mistral model is downloaded: `ollama list`
- Check if backend is running on port 8000

## Daily Usage

After initial setup, each time you want to use the app:

1. **Start Frontend**:
   ```powershell
   cd C:\Users\MARIAM\agent-security-tester
   npm run dev
   ```

2. **Start Backend** (new terminal):
   ```powershell
   cd C:\Users\MARIAM\agent-security-tester\backend
   .\venv\Scripts\activate
   python main.py
   ```

3. **Open Browser**: http://localhost:3000

4. **Stop Servers**: Press `Ctrl+C` in each terminal

## Building for Production

### Frontend
```powershell
npm run build
npm start
```

### Backend
```powershell
# Already production-ready
python main.py
```

## Need Help?

1. Check README.md for detailed documentation
2. Visit http://localhost:8000/docs for API documentation
3. Ensure all prerequisites are installed correctly
4. Verify Ollama is running: `ollama list`

---

**You're all set! Happy testing! 🚀**
