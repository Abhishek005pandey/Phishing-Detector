# 🧠 Phishing URL Detection System
> http://56.228.3.36:5000/
> A machine learning-based project to detect phishing URLs using Python, Flask, and Regex analysis — built and deployed on Ubuntu.

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Flask](https://img.shields.io/badge/Flask-2.x-green)
![MachineLearning](https://img.shields.io/badge/ML-RandomForest-orange)
![Status](https://img.shields.io/badge/Status-Completed-success)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## 🚀 Overview
The **Phishing URL Detector** is a security project that detects malicious (phishing) URLs by analyzing their structure, tokens, WHOIS data, and active behavior.  
It combines **heuristics**, **regex patterns**, and **machine learning** (Random Forest) to classify URLs as:
- ✅ *Benign (Safe)*
- ⚠️ *Suspicious*
- 🚨 *Phishing (Malicious)*

The project includes:
- A **Python CLI tool**
- A **Flask web API**
- A **Web Interface** (accessible via browser)
- Optional integration for **Android apps**

---

## 🧩 Tech Stack
| Category | Tools / Libraries |
|-----------|-------------------|
| Language | Python 3.12 |
| Framework | Flask |
| Machine Learning | Scikit-learn (RandomForestClassifier) |
| Parsing & Analysis | Regex, urllib, tldextract |
| WHOIS Lookup | python-whois |
| Frontend | HTML, JavaScript (fetch API) |
| Environment | Ubuntu 22.04 (VM on VMware Workstation) |
| Version Control | Git + GitHub |

---

## 🧠 Features
✅ Extracts and analyzes URL components (domain, subdomain, query params)  
✅ Heuristic detection for phishing keywords (`login`, `secure`, `update`, etc.)  
✅ Detects IP-based URLs, multiple redirects, suspicious patterns  
✅ WHOIS domain age lookup (to flag newly created domains)  
✅ Machine Learning classifier (Random Forest)  
✅ Flask REST API for web integration  
✅ Interactive CLI for terminal analysis  
✅ Web UI to test links in browser  

---

## 🏗️ Project Structure

