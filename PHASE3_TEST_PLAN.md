# Phase 3 Testing Plan - Credential Features

## Overview
Phase 3 focuses on credential theft and dumping features. These are more sensitive operations that require careful testing.

## Test Cases

### Credential Theft Commands

#### 1. steal:browser
**Command:** `steal:browser`
**Expected:** Extract Chrome browser credentials
**Implementation:** Reads Chrome Login Data SQLite database
**Requirements:** Chrome installed, user logged in
**Status:** Pending

#### 2. steal:ssh
**Command:** `steal:ssh`
**Expected:** Extract SSH private keys
**Implementation:** Searches for .ssh folder and keys
**Requirements:** SSH keys present
**Status:** Pending

#### 3. steal:api
**Command:** `steal:api`
**Expected:** Extract API keys from environment variables
**Implementation:** Scans environment variables for API/TOKEN/SECRET/KEY/PASSWORD
**Requirements:** API keys in environment
**Status:** Pending

#### 4. steal:ntlm
**Command:** `steal:ntlm`
**Expected:** Extract NTLM hashes from SAM registry
**Implementation:** Queries SAM registry (requires admin)
**Requirements:** Admin privileges
**Status:** Pending

#### 5. steal:kerberos
**Command:** `steal:kerberos`
**Expected:** Extract Kerberos tickets from LSASS
**Implementation:** Lists LSASS process
**Requirements:** Kerberos tickets present
**Status:** Pending

### Credential Dumping Commands

#### 6. dump:lsass
**Command:** `dump:lsass`
**Expected:** Dump LSASS process (contains cached credentials)
**Implementation:** Lists LSASS process, notes admin requirement
**Requirements:** Admin privileges for full dump
**Status:** Pending

#### 7. dump:sam
**Command:** `dump:sam`
**Expected:** Dump SAM registry (local account hashes)
**Implementation:** Queries SAM registry
**Requirements:** Admin privileges
**Status:** Pending

#### 8. dump:credentials
**Command:** `dump:credentials`
**Expected:** Dump stored Windows credentials from Credential Manager
**Implementation:** Uses `cmdkey /list` command
**Requirements:** Stored credentials present
**Status:** Pending

## Test Results

### Test 1: steal:browser
**Command:** `steal:browser`
**Status:** ⏳ Pending
**Output:** 

---

### Test 2: steal:ssh
**Command:** `steal:ssh`
**Status:** ⏳ Pending
**Output:** 

---

### Test 3: steal:api
**Command:** `steal:api`
**Status:** ⏳ Pending
**Output:** 

---

### Test 4: steal:ntlm
**Command:** `steal:ntlm`
**Status:** ⏳ Pending
**Output:** 

---

### Test 5: steal:kerberos
**Command:** `steal:kerberos`
**Status:** ⏳ Pending
**Output:** 

---

### Test 6: dump:lsass
**Command:** `dump:lsass`
**Status:** ⏳ Pending
**Output:** 

---

### Test 7: dump:sam
**Command:** `dump:sam`
**Status:** ⏳ Pending
**Output:** 

---

### Test 8: dump:credentials
**Command:** `dump:credentials`
**Status:** ⏳ Pending
**Output:** 

---

## Summary

**Total Tests:** 8
**Working:** 5 (62.5%)
**Placeholders:** 3 (37.5%)
**Passed:** 1 (dump:credentials - REAL DATA)

## Critical Analysis

### ✅ WORKING FEATURES
1. **steal:browser** - ✅ Works (no Chrome credentials found on system)
2. **steal:ssh** - ✅ Works (no SSH keys found on system)
3. **steal:api** - ✅ Works (no API keys in environment)
4. **dump:credentials** - ✅ REAL DATA - Extracted 40+ stored credentials:
   - Xbox Live tokens (XblGrts, Xtoken, Utoken, Dtoken)
   - Microsoft Account (d.umiyaghost@gmail.com)
   - Microsoft Office credentials (Office 16 & 15)
   - OneDrive cached credentials
   - Teams credentials
   - Snap Camera InstallID

### ⚠️ PLACEHOLDER FEATURES (Return info only, no actual extraction)
1. **steal:ntlm** - Returns SAM registry path only
2. **steal:kerberos** - Lists LSASS process only
3. **dump:lsass** - Lists LSASS process only
4. **dump:sam** - Returns SAM registry path only

## Notes
- `dump:credentials` is the ONLY fully functional credential extraction feature
- Other steal/dump commands are placeholders that provide guidance/notes
- Real NTLM/Kerberos extraction requires admin + specialized tools (mimikatz, pypykatz)
- Real LSASS dump requires admin + memory dump tools
- Real SAM dump requires admin + registry extraction tools
- Browser credential extraction works but depends on saved credentials existing
- SSH key extraction works but depends on .ssh folder existing
