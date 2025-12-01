"""
IoT Password Strength Checker
COMP2500 Security Principles - Final Project
Authors: Mohammed-Ali Medhat & Rye Stefani

This tool evaluates password strength specifically for IoT devices,
checking against common default passwords exploited by botnets like Mirai.
"""

import re
import hashlib
from typing import Dict, List, Tuple


class IoTPasswordChecker:
    """Password strength checker specifically designed for IoT device security"""

    # Common IoT default credentials exploited by Mirai and other botnets
    COMMON_IOT_PASSWORDS = {
        # Admin passwords
        'admin', 'password', '1234', '12345', '123456', '1234567', '12345678',
        'admin123', 'pass', 'root', 'user', 'guest', 'test', 'default',

        # Device-specific defaults
        'support', 'service', 'supervisor', 'ubnt', 'password1', 'admin1',
        '888888', '666666', '111111', '000000', 'qwerty', 'abc123',

        # Manufacturer defaults
        'smcadmin', 'realtek', 'Admin', '7ujMko0admin', 'vizxv', 'Zte521',
        'anko', 'zlxx', 'hi3518', 'jvbzd', 'klv123', 'oelinux123',

        # Common patterns
        'root123', 'admin@123', 'passw0rd', 'p@ssw0rd', 'letmein',
        'welcome', 'monkey', 'dragon', 'master', 'sunshine',

        # Numeric patterns
        '0000', '1111', '0123', '1234567890', '123123', '000000',

        # Device types
        'camera', 'dvr', 'router', 'switch', 'modem'
    }

    # Common username/password combinations used by Mirai
    COMMON_COMBINATIONS = [
        ('admin', 'admin'),
        ('root', 'root'),
        ('admin', 'password'),
        ('admin', '1234'),
        ('admin', '12345'),
        ('root', 'pass'),
        ('root', '1234'),
        ('root', 'default'),
        ('user', 'user'),
        ('admin', ''),
        ('root', ''),
        ('guest', 'guest'),
        ('support', 'support'),
        ('admin', 'admin123'),
        ('root', 'root123'),
        ('admin', 'smcadmin'),
        ('root', 'realtek'),
        ('admin', '1111'),
        ('root', 'Zte521'),
        ('admin', '7ujMko0admin')
    ]

    def __init__(self):
        """Initialize the password checker"""
        self.min_length = 12
        self.recommended_length = 16

    def check_password(self, password: str, username: str = None) -> Dict:
        """
        Comprehensive password strength check for IoT devices

        Args:
            password: The password to check
            username: Optional username to check for common combinations

        Returns:
            Dictionary containing score, strength, issues, and recommendations
        """
        if not password:
            return {
                'score': 0,
                'strength': 'CRITICAL',
                'issues': ['Empty password'],
                'recommendations': ['Password is required'],
                'is_safe': False
            }

        issues = []
        score = 100
        recommendations = []

        # Check 1: Length
        length = len(password)
        if length < 8:
            issues.append(f'Password too short ({length} characters)')
            score -= 30
            recommendations.append(f'Use at least {self.min_length} characters')
        elif length < self.min_length:
            issues.append(f'Password below recommended minimum ({length} < {self.min_length})')
            score -= 15
            recommendations.append(f'Use at least {self.min_length} characters')
        elif length >= self.recommended_length:
            score += 10

        # Check 2: Common IoT default passwords
        if password.lower() in self.COMMON_IOT_PASSWORDS:
            issues.append('Password is a known IoT default password')
            score -= 50
            recommendations.append('Never use default passwords - these are exploited by botnets like Mirai')

        # Check 3: Common username/password combinations
        if username:
            if (username.lower(), password.lower()) in self.COMMON_COMBINATIONS:
                issues.append('Username/password is a known default combination')
                score -= 50
                recommendations.append('This combination is in the Mirai botnet dictionary')

            # Username in password
            if username.lower() in password.lower():
                issues.append('Password contains username')
                score -= 20
                recommendations.append('Do not include username in password')

        # Check 4: Complexity requirements
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;/`~]', password))

        complexity_count = sum([has_upper, has_lower, has_digit, has_special])

        if complexity_count < 3:
            issues.append(f'Insufficient complexity (only {complexity_count}/4 character types)')
            score -= 20
            recommendations.append('Use uppercase, lowercase, numbers, and special characters')
        elif complexity_count < 4:
            score -= 10
            recommendations.append('Consider adding all 4 character types for maximum security')

        # Check 5: Sequential or repeated characters
        if self._has_sequential_chars(password):
            issues.append('Contains sequential characters (e.g., 123, abc)')
            score -= 15
            recommendations.append('Avoid sequential patterns')

        if self._has_repeated_chars(password):
            issues.append('Contains repeated characters')
            score -= 10
            recommendations.append('Avoid character repetition')

        # Check 6: Numeric-only passwords
        if password.isdigit():
            issues.append('Password is numeric-only')
            score -= 25
            recommendations.append('Add letters and special characters')

        # Check 7: Dictionary words (simple check)
        if self._contains_common_words(password):
            issues.append('Contains common dictionary words')
            score -= 15
            recommendations.append('Avoid common words; use random combinations')

        # Determine strength rating
        score = max(0, min(100, score))

        if score >= 80:
            strength = 'STRONG'
            is_safe = True
        elif score >= 60:
            strength = 'MODERATE'
            is_safe = True
        elif score >= 40:
            strength = 'WEAK'
            is_safe = False
        elif score >= 20:
            strength = 'VERY WEAK'
            is_safe = False
        else:
            strength = 'CRITICAL'
            is_safe = False

        return {
            'score': score,
            'strength': strength,
            'issues': issues,
            'recommendations': recommendations if not is_safe else ['Password meets security requirements'],
            'is_safe': is_safe,
            'length': length,
            'has_upper': has_upper,
            'has_lower': has_lower,
            'has_digit': has_digit,
            'has_special': has_special
        }

    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters like 123, abc, etc."""
        password_lower = password.lower()

        # Check for sequential numbers
        for i in range(len(password_lower) - 2):
            if password_lower[i:i+3].isdigit():
                nums = [int(password_lower[i+j]) for j in range(3)]
                if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                    return True
                if nums[1] == nums[0] - 1 and nums[2] == nums[1] - 1:
                    return True

        # Check for sequential letters
        for i in range(len(password_lower) - 2):
            if password_lower[i:i+3].isalpha():
                if (ord(password_lower[i+1]) == ord(password_lower[i]) + 1 and
                    ord(password_lower[i+2]) == ord(password_lower[i+1]) + 1):
                    return True

        return False

    def _has_repeated_chars(self, password: str) -> bool:
        """Check for repeated characters like aaa, 111, etc."""
        for i in range(len(password) - 2):
            if password[i] == password[i+1] == password[i+2]:
                return True
        return False

    def _contains_common_words(self, password: str) -> bool:
        """Check if password contains common dictionary words"""
        common_words = [
            'password', 'admin', 'user', 'login', 'welcome', 'letmein',
            'master', 'ninja', 'hello', 'test', 'camera', 'device',
            'router', 'switch', 'modem', 'network', 'internet', 'wifi'
        ]
        password_lower = password.lower()
        return any(word in password_lower for word in common_words)

    def generate_report(self, password: str, username: str = None) -> str:
        """Generate a detailed security report for a password"""
        result = self.check_password(password, username)

        report = []
        report.append("=" * 70)
        report.append("IoT PASSWORD SECURITY ANALYSIS")
        report.append("=" * 70)
        report.append("")

        # Overall assessment
        report.append(f"Overall Strength: {result['strength']}")
        report.append(f"Security Score: {result['score']}/100")
        report.append(f"Status: {'✓ ACCEPTABLE' if result['is_safe'] else '✗ UNACCEPTABLE'}")
        report.append("")

        # Password characteristics
        report.append("Password Characteristics:")
        report.append(f"  Length: {result['length']} characters")
        report.append(f"  Uppercase letters: {'✓' if result['has_upper'] else '✗'}")
        report.append(f"  Lowercase letters: {'✓' if result['has_lower'] else '✗'}")
        report.append(f"  Numbers: {'✓' if result['has_digit'] else '✗'}")
        report.append(f"  Special characters: {'✓' if result['has_special'] else '✗'}")
        report.append("")

        # Issues found
        if result['issues']:
            report.append("Security Issues:")
            for issue in result['issues']:
                report.append(f"  ✗ {issue}")
            report.append("")

        # Recommendations
        report.append("Recommendations:")
        for rec in result['recommendations']:
            report.append(f"  • {rec}")
        report.append("")

        # IoT-specific warnings
        if not result['is_safe']:
            report.append("⚠ WARNING: IoT Security Risk")
            report.append("  Weak passwords make devices vulnerable to botnet attacks.")
            report.append("  The Mirai botnet infected 600,000+ devices using default passwords.")
            report.append("  Change ALL default credentials immediately!")
            report.append("")

        report.append("=" * 70)

        return "\n".join(report)


def interactive_mode():
    """Run the password checker in interactive mode"""
    checker = IoTPasswordChecker()

    print("\n" + "=" * 70)
    print(" " * 18 + "IoT PASSWORD STRENGTH CHECKER")
    print(" " * 12 + "Protect Your Devices from Botnet Attacks")
    print("=" * 70)

    while True:
        print("\nOptions:")
        print("1. Check a password")
        print("2. Check username/password combination")
        print("3. Test common IoT default passwords")
        print("4. Show Mirai botnet password list")
        print("5. Exit")

        choice = input("\nSelect an option (1-5): ").strip()

        if choice == '1':
            password = input("\nEnter password to check: ")
            print("\n" + checker.generate_report(password))

        elif choice == '2':
            username = input("\nEnter username: ")
            password = input("Enter password: ")
            print("\n" + checker.generate_report(password, username))

        elif choice == '3':
            print("\n" + "=" * 70)
            print("TESTING COMMON IoT DEFAULT PASSWORDS")
            print("=" * 70)
            print("\nThese passwords are commonly exploited by botnets:\n")

            test_passwords = ['admin', 'password', '1234', '12345', 'default', 'root']
            for pwd in test_passwords:
                result = checker.check_password(pwd)
                print(f"'{pwd}': {result['strength']} (Score: {result['score']}/100)")

        elif choice == '4':
            print("\n" + "=" * 70)
            print("MIRAI BOTNET - COMMON USERNAME/PASSWORD COMBINATIONS")
            print("=" * 70)
            print("\nThese combinations were used to infect 600,000+ devices:\n")

            for username, password in checker.COMMON_COMBINATIONS[:20]:
                print(f"  {username:12} / {password if password else '(blank)'}")

            print("\n⚠ WARNING: Never use these combinations on any IoT device!")
            print("=" * 70)

        elif choice == '5':
            print("\n" + "=" * 70)
            print("Stay secure! Change all default passwords!")
            print("=" * 70 + "\n")
            break

        else:
            print("\n✗ Invalid option. Please select 1-5.")


def main():
    """Main entry point"""
    import sys

    if len(sys.argv) > 1:
        # Command-line mode
        checker = IoTPasswordChecker()
        password = sys.argv[1]
        username = sys.argv[2] if len(sys.argv) > 2 else None
        print(checker.generate_report(password, username))
    else:
        # Interactive mode
        interactive_mode()


if __name__ == "__main__":
    main()
