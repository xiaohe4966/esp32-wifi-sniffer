#!/usr/bin/env python3
"""
ESP32 WiFi Sniffer - Dictionary Generator
生成常用密码字典用于 WPA/WPA2 破解测试
"""

import argparse
import itertools
import os
import sys

# 常用基础密码
COMMON_PASSWORDS = [
    # 简单数字序列
    "12345678", "123456789", "1234567890",
    "1234567", "123456", "12345", "1234",
    "11111111", "00000000", "22222222", "99999999",
    "123123123", "321321321", "456456456",
    
    # 常见单词
    "password", "password1", "password123", "password12",
    "qwerty", "qwerty123", "qwertyuiop", "asdfghjkl",
    "abc123", "letmein", "welcome", "monkey",
    "dragon", "master", "superman", "batman",
    "iloveyou", "princess", "sunshine", "shadow",
    "football", "baseball", "basketball", "soccer",
    "admin", "root", "user", "test", "guest",
    "default", "changeme", "secret", "login",
    
    # WiFi 相关
    "wifi", "wireless", "network", "internet",
    "router", "modem", "broadband", "connect",
    "linksys", "netgear", "dlink", "tplink",
    "asus", "cisco", "huawei", "xiaomi",
    
    # 年份组合
    "2024", "2023", "2022", "2021", "2020",
    "2019", "2018", "2017", "2016", "2015",
    
    # 键盘模式
    "1q2w3e4r", "1qaz2wsx", "qazwsxedc", "zaq12wsx",
    "!@#$%^&*", "qwertyui", "asdfghjk", "zxcvbnm",
    
    # 常见组合
    "admin123", "root123", "user123", "test123",
    "password1", "pass1234", "login123", "welcome1",
    "guest123", "default1", "changeme1",
]

# 常见 SSID 名称 (用于生成针对性密码)
COMMON_SSID_PATTERNS = [
    "TP-LINK", "TPLINK", "D-Link", "DLink", "NETGEAR",
    "Linksys", "ASUS", "Xiaomi", "Huawei", "ZTE",
    "ChinaNet", "CMCC", "ChinaUnicom", "ChinaMobile",
    "MyWiFi", "Home", "Office", "Guest", "FreeWiFi",
]

# 常见数字后缀
NUMBER_SUFFIXES = ["", "1", "12", "123", "1234", "12345", "123456",
                   "0", "00", "000", "01", "001", "007",
                   "88", "888", "8888", "66", "666", "6666",
                   "99", "999", "9999", "168", "518", "520", "1314"]

# 常见特殊字符替换
CHAR_SUBSTITUTIONS = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['$', '5'],
    't': ['7'],
    'l': ['1'],
    'g': ['9'],
    'b': ['8'],
}


def generate_basic_wordlist():
    """生成基础密码列表"""
    return COMMON_PASSWORDS.copy()


def generate_ssid_based_passwords(ssid):
    """基于 SSID 生成密码变体"""
    passwords = []
    
    # 原始 SSID
    passwords.append(ssid)
    
    # 添加数字后缀
    for suffix in NUMBER_SUFFIXES:
        passwords.append(ssid + suffix)
        passwords.append(ssid.lower() + suffix)
        passwords.append(ssid.upper() + suffix)
    
    # 常见变体
    passwords.append(ssid + "wifi")
    passwords.append(ssid + "123")
    passwords.append("wifi" + ssid)
    passwords.append(ssid.replace(" ", ""))
    passwords.append(ssid.replace("-", ""))
    passwords.append(ssid.replace("_", ""))
    
    return passwords


def generate_leet_speak_variations(password):
    """生成 leet speak 变体"""
    variations = [password]
    
    # 简单替换
    for char, replacements in CHAR_SUBSTITUTIONS.items():
        new_variations = []
        for var in variations:
            if char in var.lower():
                for replacement in replacements:
                    new_var = var.replace(char, replacement)
                    new_var = var.replace(char.upper(), replacement)
                    new_variations.append(new_var)
        variations.extend(new_variations)
    
    return variations


def generate_pattern_passwords(pattern, min_len=8, max_len=16):
    """基于模式生成密码"""
    passwords = []
    
    # 年份 + 模式
    for year in range(2015, 2026):
        passwords.append(f"{pattern}{year}")
        passwords.append(f"{year}{pattern}")
    
    # 模式 + 数字
    for num in range(0, 1000):
        pwd = f"{pattern}{num:03d}"
        if min_len <= len(pwd) <= max_len:
            passwords.append(pwd)
    
    return passwords


def generate_sequential_passwords(min_len=8, max_len=10):
    """生成连续数字/字母密码"""
    passwords = []
    
    # 连续数字
    for i in range(10**(min_len-1), 10**max_len):
        passwords.append(str(i))
    
    # 键盘序列 (简化版)
    keyboard_rows = [
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890"
    ]
    
    for row in keyboard_rows:
        for i in range(len(row) - min_len + 1):
            for j in range(min_len, min(max_len + 1, len(row) - i + 1)):
                passwords.append(row[i:i+j])
    
    return passwords


def generate_date_passwords(start_year=1980, end_year=2025):
    """生成基于日期的密码"""
    passwords = []
    
    for year in range(start_year, end_year + 1):
        year_str = str(year)
        # 年份
        passwords.append(year_str)
        
        # 年月日组合
        for month in range(1, 13):
            for day in range(1, 32):
                passwords.append(f"{year_str}{month:02d}{day:02d}")
                passwords.append(f"{day:02d}{month:02d}{year_str}")
                passwords.append(f"{month:02d}{day:02d}{year_str}")
    
    return passwords


def generate_phone_passwords():
    """生成常见手机号相关密码"""
    passwords = []
    
    # 常见手机号前缀
    prefixes = ["138", "139", "135", "136", "137", "150", "151", "152", 
                "157", "158", "159", "182", "183", "187", "188"]
    
    for prefix in prefixes:
        # 前缀 + 常见后缀
        for suffix in ["00000000", "12345678", "88888888", "66666666"]:
            passwords.append(prefix + suffix)
    
    return passwords


def generate_custom_wordlist(words, numbers=True, special=True):
    """基于自定义词汇生成密码列表"""
    passwords = []
    
    for word in words:
        passwords.append(word)
        passwords.append(word.lower())
        passwords.append(word.upper())
        passwords.append(word.capitalize())
        
        # 添加数字
        if numbers:
            for i in range(1000):
                passwords.append(f"{word}{i}")
                passwords.append(f"{i}{word}")
        
        # 添加特殊字符
        if special:
            for char in ["!", "@", "#", "$", "%", "*", "&"]:
                passwords.append(f"{word}{char}")
                passwords.append(f"{char}{word}")
    
    return passwords


def remove_duplicates(passwords):
    """去重并保持顺序"""
    seen = set()
    result = []
    for pwd in passwords:
        if pwd not in seen and len(pwd) >= 8:
            seen.add(pwd)
            result.append(pwd)
    return result


def filter_by_length(passwords, min_len=8, max_len=64):
    """按长度过滤密码"""
    return [pwd for pwd in passwords if min_len <= len(pwd) <= max_len]


def save_wordlist(passwords, filename):
    """保存密码列表到文件"""
    with open(filename, 'w', encoding='utf-8') as f:
        for pwd in passwords:
            f.write(pwd + '\n')
    print(f"Saved {len(passwords)} passwords to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='ESP32 WiFi Sniffer - Dictionary Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -o wordlist.txt                    # 生成基础字典
  %(prog)s -s MyWiFi -o mywifi.txt            # 基于 SSID 生成
  %(prog)s -b -o basic.txt                    # 仅基础密码
  %(prog)s -d -o dates.txt                    # 仅日期密码
  %(prog)s --all -o full.txt                  # 生成完整字典
        """
    )
    
    parser.add_argument('-o', '--output', default='wordlist.txt',
                        help='Output filename (default: wordlist.txt)')
    parser.add_argument('-s', '--ssid',
                        help='Target SSID for SSID-based passwords')
    parser.add_argument('-b', '--basic', action='store_true',
                        help='Generate only basic passwords')
    parser.add_argument('-d', '--dates', action='store_true',
                        help='Include date-based passwords')
    parser.add_argument('-p', '--patterns', nargs='+',
                        help='Custom patterns to include')
    parser.add_argument('--min-len', type=int, default=8,
                        help='Minimum password length (default: 8)')
    parser.add_argument('--max-len', type=int, default=64,
                        help='Maximum password length (default: 64)')
    parser.add_argument('--all', action='store_true',
                        help='Generate comprehensive wordlist')
    parser.add_argument('--limit', type=int,
                        help='Limit number of passwords')
    
    args = parser.parse_args()
    
    print("ESP32 WiFi Sniffer - Dictionary Generator")
    print("=" * 50)
    
    all_passwords = []
    
    # 基础密码
    if args.basic or args.all or not any([args.dates, args.patterns]):
        print("Generating basic passwords...")
        all_passwords.extend(generate_basic_wordlist())
    
    # SSID 相关密码
    if args.ssid:
        print(f"Generating SSID-based passwords for: {args.ssid}")
        all_passwords.extend(generate_ssid_based_passwords(args.ssid))
    
    # 日期密码
    if args.dates or args.all:
        print("Generating date-based passwords...")
        all_passwords.extend(generate_date_passwords())
    
    # 自定义模式
    if args.patterns:
        print("Generating pattern-based passwords...")
        for pattern in args.patterns:
            all_passwords.extend(generate_pattern_passwords(pattern))
    
    # 完整字典额外内容
    if args.all:
        print("Generating phone-related passwords...")
        all_passwords.extend(generate_phone_passwords())
        
        print("Generating SSID pattern passwords...")
        for ssid_pattern in COMMON_SSID_PATTERNS:
            all_passwords.extend(generate_ssid_based_passwords(ssid_pattern))
    
    # 去重和过滤
    print("Removing duplicates...")
    all_passwords = remove_duplicates(all_passwords)
    
    print("Filtering by length...")
    all_passwords = filter_by_length(all_passwords, args.min_len, args.max_len)
    
    # 限制数量
    if args.limit and len(all_passwords) > args.limit:
        print(f"Limiting to {args.limit} passwords...")
        all_passwords = all_passwords[:args.limit]
    
    # 保存
    save_wordlist(all_passwords, args.output)
    
    print("=" * 50)
    print(f"Total passwords generated: {len(all_passwords)}")
    print(f"Output file: {os.path.abspath(args.output)}")


if __name__ == '__main__':
    main()
