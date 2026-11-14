#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
Data Extraction Script for:
"Performance Evaluation of Lightweight Post-Quantum Cryptography 
 for Resource-Constrained IoT Devices: An Experimental Comparative Study"

This script reads the official pqm4 benchmark repository directly from GitHub,
extracts ML-KEM and ML-DSA performance data, computes summary statistics,
and produces the tables reported in the manuscript.

Data source:
  https://raw.githubusercontent.com/mupq/pqm4/master/benchmarks.csv

The file contains four sections (Speed, Memory, Hashing, Size Evaluation),
each with its own header. The script splits the file into sections,
parses the Speed and Memory sections, and converts CPU cycles to
milliseconds assuming a 24 MHz clock.

Requirements:
  - Python 3.8+
  - requests
  - pandas

Usage:
  $ python extract_pqc_data.py

Author: [Author Name]
Date:   [Date]
License: MIT
================================================================================
"""

import csv
import io
import re
import requests
import pandas as pd


# =============================================================================
# CONFIGURATION
# =============================================================================

URL = "https://raw.githubusercontent.com/mupq/pqm4/master/benchmarks.csv"
CLOCK_KHZ = 24_000  # 24 MHz


# =============================================================================
# 1. FETCH RAW DATA
# =============================================================================

def fetch_benchmarks(url=URL):
    """Download benchmarks.csv directly into memory (no disk write)."""
    print(f"Fetching: {url}")
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    text = response.text
    print(f"[OK] Received {len(text):,} characters")
    return text


# =============================================================================
# 2. SPLIT INTO SECTIONS
# =============================================================================

def split_sections(text):
    """
    Split the benchmarks.csv into sections.

    The file structure is:
        Speed Evaluation,,,,...
        Key Encapsulation Schemes,,,,...
        Scheme,Implementation,Key Generation [cycles] (mean),...
        <rows>
        Signature Schemes,,,,...
        Scheme,Implementation,Key Generation [cycles] (mean),...
        <rows>
        Memory Evaluation,,,,...
        ...

    Returns:
        list of (section_title, header, rows)
    """
    lines = text.splitlines()
    sections = []
    current_title = None
    current_header = None
    current_rows = []

    def flush():
        nonlocal current_header, current_rows
        if current_header is not None:
            sections.append((current_title, current_header, current_rows))
        current_header = None
        current_rows = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Section title: contains "Evaluation" and is not a header row
        if "Evaluation" in stripped and not stripped.startswith("Scheme"):
            flush()
            current_title = stripped.split(",")[0].strip()
            continue

        # Header row
        if stripped.startswith("Scheme,"):
            flush()
            current_header = next(csv.reader([stripped]))
            current_rows = []
            continue

        # Data row
        if current_header is not None:
            row = next(csv.reader([stripped]))
            if len(row) == len(current_header):
                current_rows.append(row)

    flush()
    return sections


# =============================================================================
# 3. PARSE SPEED SECTION
# =============================================================================

def parse_speed_section(sections):
    """
    Return two DataFrames: one for KEM (contains 'Encapsulation'),
    one for signatures (contains 'Sign').
    """
    kem_df = None
    sig_df = None

    for title, header, rows in sections:
        if title is None or "Speed" not in title:
            continue
        if "Encapsulation [cycles] (mean)" in header and kem_df is None:
            kem_df = pd.DataFrame(rows, columns=header)
        if "Sign [cycles] (mean)" in header and sig_df is None:
            sig_df = pd.DataFrame(rows, columns=header)

    return kem_df, sig_df


# =============================================================================
# 4. PARSE MEMORY SECTION
# =============================================================================

def parse_memory_section(sections):
    """Return DataFrames for KEM and signature stack usage."""
    kem_df = None
    sig_df = None

    for title, header, rows in sections:
        if title is None or "Memory" not in title:
            continue
        if "Encapsulation [bytes]" in header and kem_df is None:
            kem_df = pd.DataFrame(rows, columns=header)
        if "Sign [bytes]" in header and sig_df is None:
            sig_df = pd.DataFrame(rows, columns=header)

    return kem_df, sig_df


# =============================================================================
# 5. CLEAN AND CONVERT
# =============================================================================

def clean_scheme(df):
    """Remove '(N executions)' suffix from scheme names."""
    df = df.copy()
    df["Scheme_clean"] = (
        df["Scheme"]
        .str.replace(r"\s*\(\d+\s*executions?\)", "", regex=True)
        .str.strip()
    )
    return df


def convert_mean_columns(df):
    """Convert columns ending with '(mean)' to numeric."""
    df = df.copy()
    for col in df.columns:
        if "(mean)" in col:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


def convert_byte_columns(df):
    """Convert columns ending with '[bytes]' to numeric."""
    df = df.copy()
    for col in df.columns:
        if "[bytes]" in col:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    return df


# =============================================================================
# 6. EXTRACT TARGET ALGORITHMS
# =============================================================================

KEM_TARGETS = {
    "ML-KEM-512":  ("ml-kem-512",  "m4fspeed"),
    "ML-KEM-768":  ("ml-kem-768",  "m4fspeed"),
    "ML-KEM-1024": ("ml-kem-1024", "m4fspeed"),
}

DSA_TARGETS = {
    "ML-DSA-44": ("ml-dsa-44", "m4f"),
    "ML-DSA-65": ("ml-dsa-65", "m4f"),
    "ML-DSA-87": ("ml-dsa-87", "m4f"),
}


def find_row(df, scheme, impl):
    subset = df[(df["Scheme_clean"] == scheme) & (df["Implementation"] == impl)]
    return subset.iloc[0] if not subset.empty else None


def extract_kem_speed(df):
    rows = []
    for label, (scheme, impl) in KEM_TARGETS.items():
        r = find_row(df, scheme, impl)
        if r is None:
            print(f"[WARN] Not found: {label}")
            continue
        rows.append({
            "Algorithm": label,
            "KeyGen_ms": r["Key Generation [cycles] (mean)"] / CLOCK_KHZ,
            "Encaps_ms": r["Encapsulation [cycles] (mean)"] / CLOCK_KHZ,
            "Decaps_ms": r["Decapsulation [cycles] (mean)"] / CLOCK_KHZ,
        })
    return pd.DataFrame(rows)


def extract_dsa_speed(df):
    rows = []
    for label, (scheme, impl) in DSA_TARGETS.items():
        r = find_row(df, scheme, impl)
        if r is None:
            print(f"[WARN] Not found: {label}")
            continue
        sign = r["Sign [cycles] (mean)"]
        verify = r["Verify [cycles] (mean)"]
        rows.append({
            "Algorithm": label,
            "KeyGen_ms": r["Key Generation [cycles] (mean)"] / CLOCK_KHZ,
            "Sign_ms": sign / CLOCK_KHZ,
            "Verify_ms": verify / CLOCK_KHZ,
            "Sign_Verify_Ratio": (sign / verify) if verify else None,
        })
    return pd.DataFrame(rows)


def extract_kem_memory(df):
    rows = []
    for label, (scheme, impl) in KEM_TARGETS.items():
        r = find_row(df, scheme, impl)
        if r is None:
            continue
        rows.append({
            "Algorithm": label,
            "KeyGen_B": r["Key Generation [bytes]"],
            "Encaps_B": r["Encapsulation [bytes]"],
            "Decaps_B": r["Decapsulation [bytes]"],
        })
    return pd.DataFrame(rows)


def extract_dsa_memory(df):
    rows = []
    # Both m4f and m4fstack variants
    for label, (scheme, _) in DSA_TARGETS.items():
        for impl in ("m4f", "m4fstack"):
            r = find_row(df, scheme, impl)
            if r is None:
                continue
            rows.append({
                "Algorithm": label,
                "Implementation": impl,
                "KeyGen_B": r["Key Generation [bytes]"],
                "Sign_B": r["Sign [bytes]"],
                "Verify_B": r["Verify [bytes]"],
            })
    return pd.DataFrame(rows)


# =============================================================================
# 7. PRINT TABLES
# =============================================================================

def print_table(df, title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)
    print(df.to_markdown(index=False, floatfmt=".2f"))
    print()


# =============================================================================
# MAIN
# =============================================================================

def main():
    # 1. Fetch
    text = fetch_benchmarks()

    # 2. Split
    sections = split_sections(text)
    print(f"[OK] Detected {len(sections)} section(s)")

    # 3. Parse Speed
    kem_speed_raw, sig_speed_raw = parse_speed_section(sections)
    if kem_speed_raw is None or sig_speed_raw is None:
        raise RuntimeError("Speed sections not found")

    kem_speed_raw = convert_mean_columns(clean_scheme(kem_speed_raw))
    sig_speed_raw = convert_mean_columns(clean_scheme(sig_speed_raw))

    # 4. Parse Memory
    kem_mem_raw, sig_mem_raw = parse_memory_section(sections)
    if kem_mem_raw is not None:
        kem_mem_raw = convert_byte_columns(clean_scheme(kem_mem_raw))
    if sig_mem_raw is not None:
        sig_mem_raw = convert_byte_columns(clean_scheme(sig_mem_raw))

    # 5. Extract
    df_kem_speed = extract_kem_speed(kem_speed_raw)
    df_dsa_speed = extract_dsa_speed(sig_speed_raw)
    df_kem_mem   = extract_kem_memory(kem_mem_raw) if kem_mem_raw is not None else None
    df_dsa_mem   = extract_dsa_memory(sig_mem_raw) if sig_mem_raw is not None else None

    # 6. Print (matches Tables 1, 2, 3 in manuscript)
    print_table(df_kem_speed, "Table 1. ML-KEM operation times (m4fspeed, 24 MHz) [ms]")
    print_table(df_dsa_speed, "Table 2. ML-DSA operation times (m4f, 24 MHz) [ms]")
    if df_kem_mem is not None:
        print_table(df_kem_mem, "Table 3a. ML-KEM peak stack usage [bytes]")
    if df_dsa_mem is not None:
        print_table(df_dsa_mem, "Table 3b. ML-DSA peak stack usage [bytes]")

    # 7. Sanity checks
    print("=" * 78)
    print("Sanity checks")
    print("=" * 78)

    if not df_kem_speed.empty:
        delta = (
            (df_kem_speed.loc[1, "KeyGen_ms"] + df_kem_speed.loc[1, "Encaps_ms"]
             + df_kem_speed.loc[1, "Decaps_ms"])
            - (df_kem_speed.loc[0, "KeyGen_ms"] + df_kem_speed.loc[0, "Encaps_ms"]
               + df_kem_speed.loc[0, "Decaps_ms"])
        ) / (df_kem_speed.loc[0, "KeyGen_ms"] + df_kem_speed.loc[0, "Encaps_ms"]
             + df_kem_speed.loc[0, "Decaps_ms"]) * 100
        print(f"  ML-KEM-768 vs ML-KEM-512 total cost overhead: {delta:.1f}%")

    if not df_dsa_speed.empty:
        for _, row in df_dsa_speed.iterrows():
            print(f"  {row['Algorithm']}: Sign/Verify = {row['Sign_Verify_Ratio']:.2f}x")


if __name__ == "__main__":
    main()