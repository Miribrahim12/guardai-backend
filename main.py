import uvicorn
import re
import sqlite3
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from transformers import pipeline

# --- 1. VERİLƏNLƏR BAZASI QURULMASI ---
# Statistikaların qalıcı olması üçün SQLite istifadə edirik
def init_db():
    conn = sqlite3.connect('guardai.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  threat_type TEXT, 
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

init_db()

# --- 2. AI VƏ REGEX SKANER MƏNTİQİ ---
class GuardScanner:
    def __init__(self):
        # Sürətli skan üçün Regex pattern-ləri
        self.patterns = {
            "EMAIL": r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
            "PHONE": r'\+?\d{10,15}',
            "CREDIT_CARD": r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}',
            "API_KEY": r'(sk|pk)_[a-z0-9]{32,}'
        }
        # Mənanı anlamaq üçün AI Modeli (Named Entity Recognition)
        # Qeyd: Bu model ilk dəfə işləyəndə internetdən kiçik bir fayl yükləyə bilər
        try:
            self.ai_engine = pipeline("ner", model="dslim/bert-base-NER", aggregation_strategy="simple")
            self.ai_enabled = True
        except:
            self.ai_enabled = False
            print("⚠️ AI Modeli yüklənmədi, yalnız Regex aktivdir.")

    def scan_text(self, text: str):
        findings = []
        
        # A. REGEX SKAN
        for entity_type, pattern in self.patterns.items():
            for match in re.finditer(pattern, text):
                findings.append({"entity_type": entity_type, "start": match.start(), "end": match.end()})
        
        # B. AI SKAN (Şəxs və Şirkət adlarını tapmaq üçün)
        if self.ai_enabled:
            ner_results = self.ai_engine(text)
            for res in ner_results:
                if res['entity_group'] in ['PER', 'ORG']:
                    findings.append({
                        "entity_type": "CONFIDENTIAL_" + res['entity_group'],
                        "start": res['start'],
                        "end": res['end']
                    })
        return findings

# --- 3. MASKER MƏNTİQİ ---
class GuardMasker:
    def mask_text(self, text, scan_results):
        sorted_results = sorted(scan_results, key=lambda x: x['start'], reverse=True)
        for res in sorted_results:
            text = text[:res['start']] + f"[{res['entity_type']}_HIDDEN]" + text[res['end']:]
        return text

# --- 4. API QURULMASI ---
app = FastAPI(title="GuardAI - AI Powered Security")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

scanner = GuardScanner()
masker = GuardMasker()

class TextPayload(BaseModel):
    content: str

# --- 5. ENDPOINTLƏR ---

@app.get("/")
def home():
    return {"status": "GuardAI v2.0 (AI Enabled) is Online"}

@app.post("/process")
async def process_text(data: TextPayload):
    threats = scanner.scan_text(data.content)
    
    # Verilənlər bazasına qeyd et
    if threats:
        conn = sqlite3.connect('guardai.db')
        c = conn.cursor()
        for t in threats:
            c.execute("INSERT INTO logs (threat_type) VALUES (?)", (t['entity_type'],))
        conn.commit()
        conn.close()
            
    safe_text = masker.mask_text(data.content, threats)
    
    return {
        "safe_text": safe_text,
        "threats_found": len(threats),
        "risk_level": "CRITICAL" if len(threats) > 2 else ("HIGH" if threats else "LOW")
    }

@app.get("/stats")
def get_stats():
    conn = sqlite3.connect('guardai.db')
    c = conn.cursor()
    
    # Ümumi statistikanı bazadan çək
    c.execute("SELECT COUNT(*) FROM logs")
    total_blocked = c.fetchone()[0]
    
    c.execute("SELECT threat_type, COUNT(*) FROM logs GROUP BY threat_type")
    distribution = dict(c.fetchall())
    
    conn.close()
    
    return {
        "total_threats_blocked": total_blocked,
        "threat_distribution": distribution
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)