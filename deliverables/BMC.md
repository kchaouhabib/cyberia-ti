# Business Model Canvas — CYBERIA TI Platform
**Target: Tier-2 / Tier-3 Banks in Emerging Markets (MENA, Africa, Eastern Europe)**

---

## 1. Customer Segments

- **Primary**: CISOs and SOC teams at Tier-2/Tier-3 banks in MENA, Africa, Eastern Europe
  - Examples: regional banks in Tunisia, Morocco, Senegal, Egypt, Romania, Georgia
  - These banks face the same APT threats as Tier-1 banks (FIN7, Lazarus, Carbanak)
    but cannot afford Recorded Future (~$150K/yr) or Mandiant retainers
- **Secondary**: MSSPs (Managed Security Service Providers) serving regional banks
- **Tertiary** (roadmap): fintech companies under PCI-DSS scope; central bank CERTs

---

## 2. Value Propositions

> *"Enterprise-grade threat intelligence for banks that can't afford Recorded Future.
> Reduce MTTA from hours to seconds and automate compliance evidence."*

- **Speed**: Reduce Mean Time To Action (MTTA) from hours (manual SOC triage) to seconds
- **Context**: Every alert is MITRE ATT&CK-mapped and translated into a CISO-ready AI summary
- **Compliance automation**: Auto-flag PCI-DSS, SWIFT CSP, GDPR, BCT breaches per incident
  — eliminates manual compliance mapping after an incident
- **Affordability**: SaaS model priced for regional banks, not Tier-1 megabanks
- **Prediction**: 7-day threat forecasts let banks pre-position defenses, not just react
- **Scalable**: same platform extends to healthcare (HIPAA, GDPR-health) and telecom (NIS2)
  by changing configuration — no code rewrite

---

## 3. Channels

- **Direct sales**: CISO-to-CISO outreach at cybersecurity conferences
  (GITEX Dubai, Cyber Africa Forum, Tunisia Cybersecurity Summit)
- **MSSP partnerships**: channel partners who bundle the platform into managed SOC services
- **Regulatory bodies**: partner with central bank cybersecurity programs
  (BCT in Tunisia, Bank Al-Maghrib in Morocco) for recommended-vendor status
- **GitHub / open-source core**: attract developers and build community trust

---

## 4. Customer Relationships

- **Self-serve onboarding**: SaaS — no professional services required for initial setup
- **Automated alerts**: platform pushes critical alerts to CISO email / Slack / SIEM
- **Compliance reports**: auto-generated PDF reports banks can file with regulators
- **MSSP white-label**: partners manage the relationship for smaller banks

---

## 5. Revenue Streams

- **Primary — SaaS subscription** (tier by bank asset size / AUM):

  | Tier | AUM | Monthly | Included Seats |
  |------|-----|---------|----------------|
  | Starter | < $1B | €299/mo | 3 analyst seats |
  | Growth  | $1–10B | €799/mo | 10 analyst seats |
  | Enterprise | $10B+ | €1,999/mo | Unlimited seats |

- **Per analyst-seat add-on**: €49/seat/month beyond included quota
- **Per data source integration**: €99/month per additional premium OSINT feed
- **Compliance report export**: Automated PDF incident reports for regulators — €199/month add-on
- **MSSP licensing**: volume discount + white-label fee (custom pricing)

---

## 6. Key Resources

- **AI pipeline**: IOC extraction (regex + LLM), classifier, deduplicator, MITRE mapper,
  compliance mapper, Prophet forecaster
- **OSINT feed access**: AlienVault OTX, URLhaus, ThreatFox, MalwareBazaar, MISP
- **Banking domain knowledge**: MITRE techniques mapped to banking TTPs,
  compliance frameworks (PCI-DSS, SWIFT CSP, GDPR, BCT)
- **Dev team**: 4-person team covering backend, AI, analysis, and product

---

## 7. Key Activities

- Continuously ingesting and processing OSINT feeds
- Running AI pipeline (extraction → classification → enrichment → correlation → prediction)
- Maintaining MITRE ATT&CK and compliance framework mappings
- Generating automated compliance evidence for regulators
- Scenario simulation for customer demos and onboarding

---

## 8. Key Partnerships

- **OSINT providers**: Abuse.ch (URLhaus, ThreatFox, MalwareBazaar), AlienVault OTX,
  CIRCL MISP community
- **MITRE ATT&CK**: open framework — no license needed, but community attribution
- **Cloud infrastructure**: hosting provider (AWS / OVH for EU/Africa compliance)
- **Regional cybersecurity consultancies**: local partners for sales and compliance guidance
- **Central bank cybersecurity programs**: BCT (Tunisia), Bank Al-Maghrib (Morocco) —
  for regulatory endorsement

---

## 9. Cost Structure

- **Cloud hosting**: FastAPI + scalable DB + inference compute
- **LLM inference**: Ollama local in MVP; OpenAI / Mistral API in production
- **Dev team salaries**: primary cost post-hackathon
- **OSINT feed licensing**: most feeds free (Abuse.ch, OTX); premium feeds are cost drivers
- **Sales & marketing**: conference attendance (GITEX, Cyber Africa Forum)
- **Compliance certification**: ISO 27001, SOC 2 Type II — required to sell to banks

---

## KPIs (Locked for Pitch)

| Metric | Value |
|--------|-------|
| MTTA reduction | Hours → seconds (automated triage) |
| MITRE techniques mapped | 7 financial-sector TTPs |
| Compliance frameworks | 5 (PCI-DSS, SWIFT CSP, GDPR, BCT, Basel III) |
| OSINT feed sources | 5+ (OTX, URLhaus, ThreatFox, MalwareBazaar, MISP) |
| Prediction horizon | 7-day Prophet forecasts per sector/threat type |
| Target addressable market | ~3,000 Tier-2/3 banks in MENA + Eastern Europe |
| Revenue target (Y1) | 20 banks × €499 avg/mo = ~€120K ARR |
