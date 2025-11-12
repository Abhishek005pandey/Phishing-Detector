# 🧠 Phishing URL Detection System
> Live demo: http://56.228.3.36:5000/  
> A machine learning-based project to detect phishing URLs using Python, Flask, and Regex analysis — built and deployed on Ubuntu (AWS EC2).

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-2.x-green)
![MachineLearning](https://img.shields.io/badge/ML-RandomForest-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## 🚀 Overview
The **Phishing URL Detector** detects malicious (phishing) URLs by analyzing structure, tokens, WHOIS data, and active behavior.  
It combines **heuristics**, **regex patterns**, and **machine learning** (Random Forest) to classify URLs as:
- ✅ *Benign (Safe)*
- ⚠️ *Suspicious*
- 🚨 *Phishing (Malicious)*

This repository contains:
- A **Python CLI** analyzer
- A **Flask** web API (`/predict` and `/analyze`)
- A simple **Web UI** for interactive testing
- Optional instructions to deploy on **AWS EC2**

---

## 🧩 Tech Stack
| Category | Tools / Libraries |
|---|---|
| Language | Python 3.12 |
| Framework | Flask |
| Machine Learning | scikit-learn (RandomForestClassifier) |
| Parsing & Analysis | Regex, `urllib`, `tldextract` |
| WHOIS Lookup | `python-whois` |
| Frontend | HTML + JavaScript (fetch API) |
| Environment | Ubuntu / AWS EC2 |
| Version Control | Git + GitHub |

---

## 🧠 Features
- Extracts and analyzes URL components (domain, subdomain, path, query)  
- Heuristic detection for phishing keywords (`login`, `secure`, `update`, etc.)  
- Detects IP-based hosts, long hex strings, multiple redirects, forms on pages  
- WHOIS domain-age lookup to flag newly created domains  
- ML classifier (Random Forest) for improved accuracy  
- Flask REST API for integration (`/predict`)  
- Interactive CLI (`src/main.py`)  
- Web UI (under `src/web/index.html`) to test URLs in-browser

---

## 📁 Project structure (short)
