# adcs.py — AD CS ESC Exploit Reference Tool

> **For use during authorized security assessments only.**

A command-line reference tool for Active Directory Certificate Services (AD CS) misconfigurations (ESC1–ESC15). Rather than executing exploits, it displays the exact tool commands needed for each attack chain — certipy, impacket, netexec (nxc), PetitPotam, Coercer, and more — with placeholder variables ready to fill in.

---

![Main Menu](screenshot.png)
<img width="729" height="535" alt="image" src="https://github.com/user-attachments/assets/7001aea0-19cb-4732-9d1f-dc71754e2d31" />


---

## Features

- Coverage of all ESC1–ESC15 misconfigurations plus general certipy enumeration and auth steps
- Full attack chains for every ESC — from initial enumeration through to DCSync
- Multiple attack paths where applicable (e.g. ESC5 covers three distinct ACL abuse routes)
- Placeholder variables (`<DC_IP>`, `<CA_NAME>`, `<DOMAIN>`, etc.) throughout — nothing runs by accident
- Color-coded output: step headers, commands, comments, and references are visually distinct
- Works interactively or as a direct lookup

## Requirements

- Python 3.6+
- No external dependencies — stdlib only

## Usage

```bash
# Interactive menu
python3 adcs.py

# Jump straight to a specific ESC
python3 adcs.py 11

# General certipy enumeration & auth steps
python3 adcs.py 0

# Dump all ESCs at once
python3 adcs.py all
```

## ESC Coverage

| # | Name | Attack Chain Summary |
|---|------|----------------------|
| 0 | General | certipy find, certipy auth, pass-the-hash, DCSync |
| 1 | Enrollee Supplies Subject | SAN abuse → cert as any user → auth |
| 2 | Any Purpose / No EKU | Enroll → use as client auth or enrollment agent |
| 3 | Enrollment Agent Abuse | Request agent cert → enroll on behalf of DA |
| 4 | Vulnerable Template ACLs | Modify template → ESC1 → restore → auth |
| 5 | Vulnerable PKI Object ACLs | Three paths: CA computer object / NTAuthCertificates / enrollment service |
| 6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | CA flag enables SAN on all templates → cert as DA |
| 7 | Vulnerable CA ACLs | ManageCA / ManageCertificates → approve requests or flip ESC6 flag |
| 8 | NTLM Relay to HTTP Enrollment | Coerce DC → relay to /certsrv/ → DC cert → PKINIT → DCSync |
| 9 | No Security Extension | UPN swap → request cert → restore → auth as target |
| 10 | Weak Certificate Mapping | UPN or sAMAccountName swap depending on registry config |
| 11 | NTLM Relay to RPC (MS-ICPR) | Coerce DC → relay to RPC endpoint → DC cert → PKINIT → DCSync |
| 12 | YubiHSM Weak PIN | Extract CA private key from HSM → forge cert → DCSync |
| 13 | Issuance Policy OID Group Link | Enroll → auth → TGT includes privileged group membership |
| 14 | altSecurityIdentities Abuse | Write explicit cert mapping to DA → auth → DCSync |
| 15 | Arbitrary EKU (Schema V1) | Specify Client Auth EKU at request time → auth |

## Tools Referenced

- [Certipy](https://github.com/ly4k/Certipy)
- [Impacket](https://github.com/fortra/impacket)
- [NetExec (nxc)](https://github.com/Pennyw0rth/NetExec)
- [PetitPotam](https://github.com/topotam/PetitPotam)
- [Coercer](https://github.com/p0dalirius/Coercer)
- [DFSCoerce](https://github.com/ly4k/DFSCoerce)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)

## References

- [Certified Pre-Owned — SpecterOps](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certipy 4.0: ESC9 & ESC10 — Oliver Lyak](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [ESC13 Abuse Technique — SpecterOps](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)
- [Relaying to AD CS over RPC — Compass Security](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)

## Disclaimer

This tool is intended for use by security professionals during authorized penetration tests and red team engagements. Unauthorized use against systems you do not have explicit permission to test is illegal. The author assumes no liability for misuse.
