import type { Rule } from '../types.js';

/**
 * Generic web-exploit probe signatures. Patterns adapted from the OWASP Core Rule
 * Set v4 (Apache-2.0) rule families; simplified substring/regex forms for log triage.
 * sfExploitable=false — these mean "you are being scanned", not "Salesforce is exploited".
 */
export const class1Rules: readonly Rule[] = [
  { id: 'c1-log4shell', family: 'Log4Shell', source: 'CRS:944150', severity: 'high',
    target: 'uri', pattern: String.raw`\$\{[^}]{0,12}(?:jndi|j\$\{|lower:|upper:|::-)`,
    sfExploitable: false, note: 'Log4j JNDI lookup, incl. common obfuscations.' },
  { id: 'c1-log4j-config', family: 'Log4j-config', source: 'custom', severity: 'low',
    target: 'uri', pattern: String.raw`log4j2?[.-][a-z]`, sfExploitable: false,
    note: 'Attempt to fetch a log4j config file.' },
  { id: 'c1-lfi-passwd', family: 'LFI', source: 'CRS:930120', severity: 'high',
    target: 'uri', pattern: String.raw`etc/passwd|\.\.[/\\]`, sfExploitable: false,
    note: 'Local file inclusion / path traversal.' },
  { id: 'c1-rfi-ssrf', family: 'RFI-SSRF', source: 'CRS:931100', severity: 'high',
    target: 'uri', pattern: String.raw`/api/cors/|rfi\.txt|interact\.sh|oastify\.com|\.nessus\.org`,
    sfExploitable: false, note: 'Remote file include / SSRF via OOB canary.' },
  { id: 'c1-crlf', family: 'CRLF', source: 'CRS:921110', severity: 'medium',
    target: 'uri', pattern: String.raw`was-header|%0d%0a| HTTP/1\.1`, sfExploitable: false,
    note: 'CRLF / HTTP response splitting probe.' },
  { id: 'c1-struts', family: 'Struts2', source: 'CRS:932100', severity: 'high',
    target: 'uri', pattern: String.raw`struts2?-|\.action\b|webconsole\.html`, sfExploitable: false,
    note: 'Struts2 OGNL showcase probe.' },
  { id: 'c1-rwservlet', family: 'Oracle-Reports', source: 'custom', severity: 'medium',
    target: 'uri', pattern: String.raw`rwservlet`, sfExploitable: false,
    note: 'Oracle Reports rwservlet probe.' },
  { id: 'c1-actuator', family: 'Spring-Actuator', source: 'custom', severity: 'medium',
    target: 'uri', pattern: String.raw`/actuator(/|$)`, sfExploitable: false,
    note: 'Spring Boot Actuator exposure probe.' },
  { id: 'c1-pentaho', family: 'Pentaho', source: 'custom', severity: 'medium',
    target: 'uri', pattern: String.raw`pentaho/api/ldap`, sfExploitable: false,
    note: 'Pentaho LDAP config probe.' },
  { id: 'c1-git', family: 'Exposed-git', source: 'CRS:913120', severity: 'medium',
    target: 'uri', pattern: String.raw`/\.git(/|$)|/\.github/`, sfExploitable: false,
    note: 'Exposed .git / CI config probe.' },
  { id: 'c1-env', family: 'Exposed-env', source: 'CRS:913120', severity: 'medium',
    target: 'uri', pattern: String.raw`/\.env(\.|$|/)`, sfExploitable: false,
    note: 'Exposed .env secrets probe.' },
];
