# CONFIDENTIAL - SECURITY ASSESSMENT REPORT

## Penetration Testing Report for 10root

**Report Date**: May 14, 2025
**Assessment Period**: April 23 - May 7, 2025
**Report Version**: 1.0
**Classification**: CONFIDENTIAL

### 1. Executive Summary

This report presents the findings of a comprehensive penetration test conducted on 10root's IT infrastructure and applications. The assessment identified several critical and high-risk vulnerabilities that could potentially expose sensitive customer data and business information to unauthorized access.

10root (https://www.10root.com) requested this penetration test to evaluate their security posture prior to launching their new cloud security platform. Our team conducted external and internal network testing, web application assessments, and social engineering tests.

### 2. Company Information

**Client Details:**
- Company Name: 10root, Inc.
- Primary Domain: 10root.com
- IP Range: 198.51.100.0/24
- Main Office: 1234 Cyber Street, Suite 567, San Francisco, CA 94105
- Data Center: 5678 Server Lane, Santa Clara, CA 95051

**Key Contacts:**
- Sarah Johnson, CTO (sarah.johnson@10root.com, +1-415-555-7890)
- Michael Chen, CISO (michael.chen@10root.com, +1-415-555-1234)
- Security Operations Center (soc@10root.com, +1-415-555-9876)
- IT Support (support@10root.com, +1-415-555-4321)
- Emergency Contact (emergency@10root.com, +1-415-555-0911)

### 3. Assessment Scope

The penetration test included the following:

- External network (198.51.100.0/24)
- Web applications:
  - https://www.10root.com
  - https://portal.10root.com
  - https://api.10root.com
  - https://admin.10root.com
  - https://support.10root.com
- Internal network (10.10.0.0/16)
- AWS cloud infrastructure (account ID: 012345678901)
- Social engineering assessment

### 4. High-Risk Findings

#### 4.1. Exposed API Credentials

**Risk Rating: Critical**

During our review of the GitHub repositories, we found exposed AWS access keys in the repository 10root/cloud-scanner. The following API credentials were committed to the repository on March 12, 2025:

- API Key: AKIAxxxxxxxxxxxxxxxxxxx
- API Secret: bT9xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

These credentials were traced to David Wilson's AWS account (david.wilson@10root.com, 054-987-6543). The exposed keys have administrator privileges and could allow attackers to access all 10root AWS resources.

#### 4.2. Vulnerable Authentication in Customer Portal

**Risk Rating: Critical**

The customer portal (https://portal.10root.com) was found to be vulnerable to session fixation attacks. Testing conducted by our team confirmed that attacker-provided session tokens remain valid after authentication. The vulnerability affects all portal users including:

- Enterprise customers (acme@portal.10root.com, microsoft@portal.10root.com, amazon@portal.10root.com)
- Partner accounts (partners@10root.com)
- Administrative users (admin@portal.10root.com)

#### 4.3. SQL Injection in API Endpoint

**Risk Rating: High**

The following API endpoint is vulnerable to SQL injection:
- https://api.10root.com/v1/customers/search

Test credentials used:
- Username: api_test_user@10root.com
- Password: Test_Api_2025!
- API Key: 29af7989-4c76-4832-b522-3ce8944a2ce1

This vulnerability could allow extraction of sensitive customer data including credit card information. During testing, we were able to extract sample data including:

- Customer: Acme Corp
  - Contact: John Smith
  - Email: john.smith@acme.com
  - Credit Card: 4111 1111 1111 1111
  - Expiry: 12/26

- Customer: TechSolutions Inc.
  - Contact: Mary Johnson
  - Email: mjohnson@techsolutions.net
  - Credit Card: 5555 5555 5555 4444
  - Expiry: 10/27

### 5. Medium-Risk Findings

#### 5.1. Insecure Direct Object References

**Risk Rating: Medium**

The support ticket system (https://support.10root.com) suffers from IDOR vulnerabilities, allowing authenticated users to access other customers' support tickets. The following endpoints are affected:

- https://support.10root.com/tickets/view/[TICKET_ID]
- https://support.10root.com/tickets/download/[ATTACHMENT_ID]

Test accounts used:
- test.user1@10root.com / Password123!
- test.user2@10root.com / SecurePass2025!

#### 5.2. Missing MFA for Admin Access

**Risk Rating: Medium**

Administrative accounts can access sensitive systems without multi-factor authentication. The following admin accounts were identified without MFA enabled:

- admin.user@10root.com (John Adams, IT Admin)
- db.admin@10root.com (Elena Rodriguez, Database Admin)
- sys.admin@10root.com (Terry Zhang, Systems Admin)
- security.admin@10root.com (Alex Washington, Security Admin)

Administrator contact information:
- John Adams: +1-415-555-2001, john.adams@10root.com
- Elena Rodriguez: +1-415-555-2002, elena.rodriguez@10root.com
- Terry Zhang: +1-415-555-2003, terry.zhang@10root.com
- Alex Washington: +1-415-555-2004, alex.washington@10root.com

#### 5.3. Sensitive Data Stored on Public S3 Bucket

**Risk Rating: Medium**

The following S3 bucket was found to be publicly accessible:
- s3://10root-customer-backup/

This bucket contained customer contracts, including:
- Contract ID: CONT-2025-03-0123
  - Customer: GlobalTech Co.
  - Contact: James Peterson, james.peterson@globaltech.com, +1-312-555-8765
  - Credit Card: 3782 8224 6310 005
  - Contract Value: $250,000

- Contract ID: CONT-2025-02-0456
  - Customer: SecureCorp
  - Contact: Lisa Miller, lmiller@securecorp.net, +1-212-555-1122
  - Credit Card: 6011 0009 9013 9424
  - Contract Value: $175,000

### 6. Additional Findings

Our testing also revealed a number of lower-risk issues:

- 10root.com DNS servers exposed version information
- Outdated web server software on legacy.10root.com (Apache 2.2.15)
- Unencrypted internal communications between 10.10.1.5 and 10.10.2.10
- Password policy does not enforce sufficient complexity for standard users

### 7. Recommendations

Based on our findings, we recommend the following immediate actions:

1. Rotate all exposed AWS credentials and implement AWS CloudTrail logging to monitor for suspicious activity
2. Implement secure session management on the customer portal with proper token handling
3. Apply proper input validation and parameterized queries to the vulnerable API endpoint
4. Implement proper authorization checks in the support ticket system
5. Enforce MFA for all administrative accounts
6. Review and secure all S3 bucket permissions and implement encryption for sensitive data

### 8. Conclusion

10root's overall security posture requires significant improvement before launching the new cloud security platform. The critical vulnerabilities identified present substantial risk to the organization and its customers. We recommend addressing the critical findings immediately and developing a remediation plan for the remaining issues.

### 9. Appendices

#### 9.1. Team Members

- Lead Penetration Tester: Daniel Brown (daniel.brown@securityfirm.com, +1-650-555-7777)
- Web Application Specialist: Jennifer Lee (jennifer.lee@securityfirm.com, +1-650-555-8888)
- Network Security Analyst: Mark Williams (mark.williams@securityfirm.com, +1-650-555-9999)
- Social Engineering Specialist: Rachel Green (rachel.green@securityfirm.com, +1-650-555-6666)

#### 9.2. Testing Methodology

Our testing methodology followed the OWASP Testing Guide and NIST SP 800-115 guidelines. We applied a risk-based approach, focusing on high-value assets and potential attack vectors.

---

*This report contains sensitive information and should be handled according to 10root's data classification policies. Distribution should be limited to authorized individuals only.*

**CONFIDENTIAL - DO NOT DISTRIBUTE**