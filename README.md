# IoT Security Vulnerability Analysis

**COMP2500 Security Principles - Final Project**
**Authors:** Mohammed-Ali Medhat & Rye Stefani

## 📖 Project Overview

This project presents a comprehensive analysis of security vulnerabilities in Internet of Things (IoT) devices, based on research from 25+ academic papers. We examine critical security weaknesses, analyze real-world attack case studies (particularly the Mirai botnet), and provide practical security recommendations.

## 🔍 Key Findings

Based on our research analysis:

- **82%** of papers identified weak authentication as a critical vulnerability
- **68%** reported unencrypted data transmission issues
- **71%** highlighted privacy concerns from excessive data collection
- **54%** documented insecure or absent firmware update mechanisms
- **36%** noted physical security vulnerabilities

## 🚨 Case Study: Mirai Botnet (2016)

The Mirai botnet demonstrated the catastrophic impact of weak IoT security:

- **600,000+ devices** infected worldwide
- **Attack method:** Exploitation of default username/password combinations
- **Impact:** Massive DDoS attacks against Twitter, Netflix, GitHub, and other major services
- **Attack size:** 620 Gbps (largest at the time)
- **Root cause:** Manufacturers shipping devices with default credentials

## 🔐 IoT Password Strength Checker

We've developed an interactive tool to demonstrate password security principles for IoT devices. The tool performs comprehensive security analysis by checking passwords against:

- **Common IoT default passwords** exploited by the Mirai botnet
- **Password complexity** requirements (length, character types)
- **Known username/password combinations** used in botnet attacks
- **Security anti-patterns** (sequential characters, repetition, dictionary words)

### Usage:

**Interactive Mode:**
```bash
python3 iot_password_checker.py
```

The interactive mode provides:
1. Single password strength checking
2. Username/password combination analysis
3. Testing against common IoT default passwords
4. Display of Mirai botnet credential dictionary

**Command-line Mode:**
```bash
# Check a single password
python3 iot_password_checker.py "MyP@ssw0rd123"

# Check username/password combination
python3 iot_password_checker.py "MyP@ssw0rd123" "admin"
```

### Features:
- ✓ Comprehensive security scoring system (0-100)
- ✓ Detailed analysis with specific security issues identified
- ✓ Actionable recommendations for improvement
- ✓ Database of 60+ common IoT default passwords
- ✓ Detection of Mirai botnet credential combinations
- ✓ Real-time strength assessment with visual indicators

### Example Output:

```
======================================================================
IoT PASSWORD SECURITY ANALYSIS
======================================================================

Overall Strength: CRITICAL
Security Score: 0/100
Status: ✗ UNACCEPTABLE

Password Characteristics:
  Length: 5 characters
  Uppercase letters: ✗
  Lowercase letters: ✓
  Numbers: ✗
  Special characters: ✗

Security Issues:
  ✗ Password is a known IoT default password
  ✗ Username/password is a known default combination
  ✗ Insufficient complexity (only 1/4 character types)

⚠ WARNING: IoT Security Risk
  Weak passwords make devices vulnerable to botnet attacks.
  The Mirai botnet infected 600,000+ devices using default passwords.
  Change ALL default credentials immediately!
```

## 📊 Security Demonstration

Run the security findings demonstration:

```bash
python3 sample_demo
```

This interactive script walks through:
- Research vulnerability statistics
- Mirai botnet case study details
- Security recommendations based on our analysis

## 🛡️ Security Recommendations

Based on our comprehensive analysis, we recommend:

1. **Mandatory unique passwords** - Never use default credentials on any IoT device
2. **Network segmentation** - Isolate IoT devices from critical systems
3. **Automatic secure updates** - Implement cryptographically signed firmware updates
4. **End-to-end encryption** - Encrypt all data transmission by default
5. **Industry standards** - Adopt and enforce IoT security certification standards

### Password Best Practices for IoT:

- ✓ Use passwords with **12+ characters** (16+ recommended)
- ✓ Include **all 4 character types**: uppercase, lowercase, numbers, symbols
- ✓ **Change default credentials** immediately upon device setup
- ✓ Use **unique passwords** for each device
- ✗ Never use passwords from the Mirai dictionary
- ✗ Avoid sequential patterns (123, abc) or repetition (aaa, 111)
- ✗ Don't include usernames or device names in passwords

## 📁 Repository Structure

```
iot-security-analysis/
├── README.md                  ← Project documentation (this file)
├── sample_demo                ← Interactive security findings presentation
└── iot_password_checker.py    ← IoT password strength analysis tool
```

## 🎓 Educational Purpose

This project is designed for educational purposes to raise awareness about IoT security vulnerabilities and demonstrate the importance of strong authentication mechanisms. The password checker tool can be used to:

- Train users on password security principles
- Demonstrate the weaknesses exploited by real-world attacks
- Provide practical security assessment capabilities
- Educate developers on secure IoT device configuration

## 📚 References

This project synthesizes findings from 25+ peer-reviewed research papers on IoT security, with particular focus on:
- Authentication vulnerabilities
- Botnet attack methodologies
- Real-world security incidents
- Mitigation strategies and best practices

---

**Key Takeaway:** IoT devices are critically vulnerable due to weak authentication. Simple, low-cost solutions exist (strong passwords, network segmentation, secure updates) but are not widely implemented by manufacturers. Users must take proactive steps to secure their devices.

## 🤝 Contributing

This project was developed as part of COMP2500 Security Principles coursework. For questions or suggestions, please contact the authors.

---

**Stay Secure!** Always change default passwords and keep your IoT devices updated.
