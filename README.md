# AI Agent Security Tester

A modern, professional platform for security and vulnerability testing of AI agents and MCP servers using MAESTRO and ATFAA frameworks.

![Platform](https://img.shields.io/badge/Platform-Next.js%2014-black)
![Backend](https://img.shields.io/badge/Backend-FastAPI-009688)
![Model](https://img.shields.io/badge/Model-Mistral-orange)
![Framework](https://img.shields.io/badge/Framework-MAESTRO%20%26%20ATFAA-blue)

## 🎯 Features

- **Modern UI/UX**: Beautiful gradient design with glass morphism effects
- **Real-time Analysis**: Analyze AI agents for security vulnerabilities
- **MAESTRO Framework**: Architecture decomposition and analysis
- **ATFAA Framework**: Behavioral threat identification
- **JSON Export**: Download detailed mission files
- **Extensible**: Easy to add new features and components

## 🏗️ Tech Stack

### Frontend
- **Next.js 14** - React framework with App Router
- **TypeScript** - Type-safe development
- **Tailwind CSS** - Utility-first styling
- **Framer Motion** - Smooth animations
- **React Hot Toast** - Beautiful notifications

### Backend
- **FastAPI** - Modern Python web framework
- **LangChain** - LLM orchestration
- **Ollama** - Local LLM runtime
- **Mistral** - AI model for analysis
- **Pydantic** - Data validation

## 📋 Prerequisites

Before running this project, make sure you have:

1. **Node.js** (v18 or higher)
   - Download from [nodejs.org](https://nodejs.org/)
   - Verify: `node --version`

2. **Python** (v3.10 or higher)
   - Download from [python.org](https://www.python.org/)
   - Verify: `python --version`

3. **Ollama**
   - Download from [ollama.ai](https://ollama.ai/)
   - Verify: `ollama --version`

4. **Mistral Model**
   - Run: `ollama pull mistral:latest`
   - Verify: `ollama list`

## 🚀 Installation & Setup

### 1. Clone or Navigate to Project

```bash
cd C:\Users\MARIAM\agent-security-tester
```

### 2. Frontend Setup

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will be available at: **http://localhost:3000**

### 3. Backend Setup

Open a new terminal:

```bash
# Navigate to backend directory
cd backend

# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Mac/Linux:
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
python main.py
```

The backend API will be available at: **http://localhost:8000**

### 4. Verify Ollama is Running

Make sure Ollama is running with Mistral:

```bash
# Check if Mistral is installed
ollama list

# If not installed, pull it
ollama pull mistral:latest

# Ollama should be running (it usually starts automatically)
```

## 📖 Usage

1. **Start Both Servers**
   - Frontend: `npm run dev` (Port 3000)
   - Backend: `python backend/main.py` (Port 8000)

2. **Open Browser**
   - Navigate to http://localhost:3000

3. **Enter Agent Description**
   - Click "Load Example" or paste your agent description
   - Example format:
   ```
   Agent: 'Your-Agent-Name'
   Mission: What the agent does
   Tools: list_of_tools
   Data: Data sources it uses
   ```

4. **Click "Start Security Analysis"**
   - Wait for the analysis (10-30 seconds)
   - View detailed vulnerability report
   - Export JSON mission file

## 🎨 UI Features

### Modern Design Elements
- **Animated Gradients**: Smooth background animations
- **Glass Morphism**: Translucent card effects
- **Responsive Layout**: Works on all screen sizes
- **Real-time Feedback**: Loading states and toasts
- **Syntax Highlighting**: Beautiful JSON output
- **Priority Badges**: Color-coded vulnerability levels

### Color-Coded Priorities
- 🔴 **CRITICAL** - Immediate action required
- 🟠 **HIGH** - Significant risk
- 🟡 **MEDIUM** - Moderate risk
- 🔵 **LOW** - Minor risk

## 📁 Project Structure

```
agent-security-tester/
├── app/
│   ├── globals.css          # Global styles
│   ├── layout.tsx           # Root layout
│   └── page.tsx             # Main page
├── components/
│   ├── AgentInput.tsx       # Input component
│   └── ResultsDisplay.tsx   # Results component
├── types/
│   └── index.ts             # TypeScript types
├── backend/
│   ├── main.py              # FastAPI server
│   ├── models.py            # Pydantic models
│   ├── analysis_service.py  # Analysis logic
│   └── requirements.txt     # Python dependencies
├── package.json             # Node dependencies
├── tsconfig.json            # TypeScript config
├── tailwind.config.js       # Tailwind config
└── next.config.js           # Next.js config
```

## 🔧 Extending the Platform

### Adding New Analysis Features

1. **Update Backend Models** (`backend/models.py`)
   ```python
   class NewFeature(BaseModel):
       field: str
   ```

2. **Modify Analysis Service** (`backend/analysis_service.py`)
   ```python
   async def new_analysis_method(self, data: str):
       # Your logic here
   ```

3. **Add API Endpoint** (`backend/main.py`)
   ```python
   @app.post("/api/new-feature")
   async def new_feature(request: Request):
       # Your endpoint logic
   ```

### Adding New UI Components

1. **Create Component** (`components/NewComponent.tsx`)
   ```typescript
   export default function NewComponent() {
       return <div>...</div>
   }
   ```

2. **Update Main Page** (`app/page.tsx`)
   ```typescript
   import NewComponent from '@/components/NewComponent'
   ```

### Customizing Styles

Edit `tailwind.config.js` to add custom colors, animations, etc:

```javascript
theme: {
  extend: {
    colors: {
      custom: '#hexcode'
    }
  }
}
```

## 🐛 Troubleshooting

### Frontend Issues

**Port 3000 already in use:**
```bash
# Windows
netstat -ano | findstr :3000
taskkill /PID <PID> /F

# Or use different port
npm run dev -- -p 3001
```

**Dependencies not installing:**
```bash
# Clear cache
npm cache clean --force
rm -rf node_modules package-lock.json
npm install
```

### Backend Issues

**Ollama not responding:**
```bash
# Restart Ollama service
# Windows: Check Task Manager
# Mac/Linux: ollama serve
```

**Model not found:**
```bash
# Pull Mistral model again
ollama pull mistral:latest
```

**CORS errors:**
- Make sure backend is running on port 8000
- Check CORS settings in `backend/main.py`

## 📊 API Documentation

Once the backend is running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## 🔒 Security Considerations

This is a security testing tool. When deploying:
1. Enable authentication
2. Use environment variables for sensitive data
3. Implement rate limiting
4. Use HTTPS in production
5. Validate all inputs
6. Implement proper logging

## 📝 License

This project is for educational purposes as part of a graduation project.

## 👥 Contributing

This is a graduation project. To extend:
1. Fork the repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit pull request

## 🎓 Academic Context

**Project**: Security and Vulnerability Testing for AI Agents and MCP Servers  
**Frameworks**: MAESTRO (Architecture) & ATFAA (Threat Modeling)  
**Model**: Mistral (via Ollama)

## 📞 Support

For issues or questions:
1. Check troubleshooting section
2. Review API documentation
3. Check Ollama status
4. Verify all dependencies are installed

---

**Made with ❤️ for AI Security Research**
