<div align="center">

# 💰 FinanceOS – Personal Finance Management System

**A full-stack personal finance dashboard built with Flask & PostgreSQL. Track income, expenses, investments, and savings — with beautiful charts, smart alerts, and tax calculation.**

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Neon-336791?logo=postgresql&logoColor=white)](https://neon.tech)
[![Vercel](https://img.shields.io/badge/Deploy-Vercel-000000?logo=vercel&logoColor=white)](https://vercel.com)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952B3?logo=bootstrap&logoColor=white)](https://getbootstrap.com)

</div>

---

## 📸 Screenshots

| Dashboard | Analysis | Tax Calculator |
|-----------|----------|----------------|
| ![Dashboard](screenshots/dashboard.png) | ![Analysis](screenshots/analysis.png) | ![Tax](screenshots/tax.png) |

---

## ✨ Features

### Core Finance Management
- ✅ **Transaction Tracking** – Add, edit, and delete Income, Expense, and Investment records
- ✅ **Real-time Dashboard** – KPI tiles for Total Income, Expenses, Investments, and Net Savings
- ✅ **Interactive Charts** – Monthly bar chart, income/expense doughnut, category pie charts
- ✅ **Monthly Summary** – Month-wise breakdown table on the dashboard
- ✅ **Recent Transactions** – Last 5 transactions at a glance

### Analysis & Reporting
- ✅ **Advanced Filtering** – Filter by date range, month, year, transaction type, or category keyword
- ✅ **Sortable Table** – Click column headers to sort transactions
- ✅ **Pagination** – 10 records per page with smooth navigation
- ✅ **CSV Export** – Download all transactions as a CSV file in one click
- ✅ **Trend Charts** – Income and expense trend line charts over time

### Smart Alerts
- ✅ **Expense Alerts** – Notify when cumulative spending exceeds a threshold
- ✅ **Income Alerts** – Notify when earnings fall below a target
- ✅ **Toggle / Edit / Delete** – Full alert lifecycle management

### Tax Calculator
- ✅ **Old & New Regime** – Accurate calculation for both tax regimes (FY 2024-25)
- ✅ **Advance Tax Schedule** – June / September / December / March installments
- ✅ **PDF Export** – Download summary as PDF (local only, requires wkhtmltopdf)
- ✅ **Effective Rate Display** – Shows your effective tax rate as a percentage

### User Management
- ✅ **Secure Registration & Login** – bcrypt password hashing
- ✅ **OTP-based Password Reset** – Email OTP flow via Flask-Mail
- ✅ **Profile Management** – Update name and email
- ✅ **Session Management** – Auto-expiry after 25 minutes of inactivity

### UX & Design
- ✅ **Dark / Light Mode** – Persistent theme toggle across all pages
- ✅ **Responsive Sidebar** – Fixed navigation with hamburger on mobile
- ✅ **Bootstrap 5 + Bootstrap Icons** – Modern SaaS dashboard aesthetic
- ✅ **Categorized Flash Messages** – Color-coded success / warning / danger / info toasts
- ✅ **Client-side Validation** – Instant form feedback without round-trips

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python, Flask 3.0, Flask-SQLAlchemy |
| Database | PostgreSQL (Neon) / SQLite (local dev) |
| Auth | bcrypt password hashing, Flask-Session |
| Email | Flask-Mail (Gmail SMTP) |
| Data | Pandas, NumPy |
| Frontend | Bootstrap 5.3, Bootstrap Icons, Chart.js 4 |
| Font | Inter (Google Fonts) |
| Deployment | Vercel (@vercel/python) + Neon DB |

---

## 🚀 Local Installation

### Prerequisites
- Python 3.10+
- pip

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/personal-finance-management.git
cd personal-finance-management

# 2. Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set up environment variables
copy .env.example .env
# Edit .env and fill in your values (leave DATABASE_URL blank to use SQLite)

# 5. Run the development server
python main.py
```

Open **http://localhost:5000** in your browser.

> **SQLite fallback**: If `DATABASE_URL` is not set in `.env`, the app automatically uses a local `finance.db` SQLite file — no database setup required.

---

## ☁️ Vercel + Neon Deployment

### Step 1: Create a Neon Database
1. Sign up at [neon.tech](https://neon.tech) (free tier available)
2. Create a new project → new database
3. Copy the **Connection String** from Settings → it looks like:
   ```
   postgresql://user:password@ep-xxx.neon.tech/dbname?sslmode=require
   ```

### Step 2: Deploy to Vercel
1. Push your code to GitHub
2. Go to [vercel.com](https://vercel.com) → **New Project** → Import your repo
3. Add these **Environment Variables** in Vercel project settings:

   | Variable | Value |
   |----------|-------|
   | `DATABASE_URL` | Your Neon connection string |
   | `SECRET_KEY` | A long random string |
   | `MAIL_USERNAME` | Your Gmail address |
   | `MAIL_PASSWORD` | Your Gmail App Password |

4. Click **Deploy** – Vercel will detect `vercel.json` and use `api/index.py` as the entry point.

> **Tables**: SQLAlchemy will automatically create all database tables on first request via `db.create_all()`.

### Step 3: Verify
Visit your Vercel URL, register an account, and add transactions. They will persist in Neon PostgreSQL.

---

## 📁 Project Structure

```
Personal_Finance_Management_System/
├── main.py              # Flask app, routes, SQLAlchemy models
├── support.py           # Pandas/data helper functions
├── requirements.txt     # Python dependencies
├── vercel.json          # Vercel deployment config
├── .env.example         # Environment variable template
├── api/
│   └── index.py         # Vercel WSGI entry point
├── templates/
│   ├── base.html        # Shared layout (sidebar, topbar, flash)
│   ├── login.html       # Login page
│   ├── register.html    # Registration page
│   ├── home.html        # Dashboard
│   ├── analysis.html    # Analysis & transactions table
│   ├── alerts.html      # Smart alerts management
│   ├── profile.html     # User profile
│   ├── contact.html     # Contact form
│   ├── tax_form.html    # Tax calculator input
│   ├── tax_calculation.html  # Tax results
│   ├── verify_otp.html  # OTP verification
│   └── pdf_tax_summary.html  # PDF template
└── static/
    ├── css/
    ├── js/
    └── images/
```

---

## 📄 License

MIT License – see [LICENSE](LICENSE) for details.
