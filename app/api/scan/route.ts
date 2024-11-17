import { NextResponse } from 'next/server'
import https from 'https'
import { parse } from 'url'
import { JSDOM } from 'jsdom'
import type { TLSSocket } from 'tls'
import type { DetailedPeerCertificate } from 'tls'


export async function POST(req: Request) {
  const { url } = await req.json()

  if (!url || !url.startsWith('https://')) {
    return NextResponse.json({ error: 'Valid HTTPS URL is required' }, { status: 400 })
  }

  try {
    const results = await performScan(url)
    return NextResponse.json(results)
  } catch (err) {
    console.error('Scan error:', err)
    return NextResponse.json({ error: err.message }, { status: 500 })
  }
}

async function performScan(url: string) {
  const parsedUrl = parse(url)
  
  if (!parsedUrl.hostname) {
    throw new Error('Invalid URL format')
  }

  const options = {
    hostname: parsedUrl.hostname,
    port: 443,
    path: parsedUrl.path || '/',
    method: 'GET',
    rejectUnauthorized: false,
    timeout: 10000,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': '*/*',
      'Connection': 'close'
    },
    agent: new https.Agent({
      keepAlive: false,
      maxSockets: 1,
      rejectUnauthorized: false,
      timeout: 10000
    })
  }

  return new Promise((resolve, reject) => {
    let responseData = ''
    let isRequestClosed = false
    let responseTimeout: NodeJS.Timeout

    const cleanup = () => {
      if (responseTimeout) clearTimeout(responseTimeout)
      if (!isRequestClosed) {
        isRequestClosed = true
        if (req && !req.destroyed) req.destroy()
      }
    }

    const req = https.request(options, (res) => {
      responseTimeout = setTimeout(() => {
        cleanup()
        reject(new Error('Response timeout'))
      }, 10000)

      let size = 0
      const maxSize = 1024 * 1024

      res.on('data', (chunk) => {
        size += chunk.length
        if (size > maxSize) {
          cleanup()
          reject(new Error('Response too large'))
          return
        }
        responseData += chunk
      })

      res.on('end', () => {
        if (isRequestClosed) return
        try {
          const socket = req.socket as TLSSocket
          const results = {
            sslCertificate: checkSSLCertificate(socket),
            sqlInjection: checkSQLInjection(responseData),
            xss: checkXSS(responseData),
            httpHeaders: checkHTTPHeaders(res.headers as Record<string, string | string[]>),
            csrf: checkCSRF(responseData, res.headers as Record<string, string | string[]>),
            ssrf: checkSSRF(responseData),
            idor: checkIDOR(responseData),
            ldap: checkLDAP(responseData),
          }

          // Calculate overall score
          const overallScore = calculateOverallScore(results);
          results.overallScore = overallScore; // Add overall score to results

          cleanup()
          resolve(results)
        } catch (error) {
          cleanup()
          reject(new Error('Failed to process scan results'))
        }
      })
    })

    req.on('error', (error) => {
      cleanup()
      reject(new Error(`Connection failed: ${error.message}`))
    })

    req.on('timeout', () => {
      cleanup()
      reject(new Error('Request timed out'))
    })

    req.on('socket', (socket) => {
      socket.on('error', (error) => {
        cleanup()
        reject(new Error(`Socket error: ${error.message}`))
      })
    })

    req.setTimeout(10000)

    req.end()
  })
}

function checkSSLCertificate(socket: TLSSocket) {
  try {
    if (!socket || !socket.getPeerCertificate || socket.destroyed) {
      return createDefaultResponse('Not using a secure TLS connection');
    }

    const cert = socket.getPeerCertificate(true);

    if (!cert || Object.keys(cert).length === 0) {
      return createDefaultResponse('No SSL certificate present');
    }

    const certInfo = {
      issuer: extractIssuer(cert),
      subject: extractSubject(cert),
      validFrom: cert.valid_from,
      validTo: cert.valid_to,
      serialNumber: cert.serialNumber,
      signatureAlgorithm: cert.signatureAlgorithm,
      fingerprint: cert.fingerprint,
    };

    const currentDate = new Date();
    const validFrom = new Date(certInfo.validFrom);
    const validTo = new Date(certInfo.validTo);

    const checks = {
      expired: currentDate > validTo,
      notYetValid: currentDate < validFrom,
      selfSigned: isSelfSigned(cert),
      authorized: socket.authorized,
      validChain: hasValidChain(cert)
    };

    const issues = [];
    if (checks.expired) issues.push('Certificate has expired');
    if (checks.notYetValid) issues.push('Certificate not yet valid');
    if (checks.selfSigned) issues.push('Self-signed certificate detected');
    if (!checks.authorized) issues.push('Certificate not authorized');
    if (!checks.validChain) issues.push('Invalid certificate chain');

    const isSecure = issues.length === 0 && checks.authorized;

    return {
      status: isSecure ? 'secure' : 'vulnerable',
      details: isSecure 
        ? `Valid certificate from ${certInfo.issuer}`
        : issues.join(', '),
      issuer: certInfo.issuer,
      subject: certInfo.subject,
      validFrom: certInfo.validFrom,
      validTo: certInfo.validTo,
      serialNumber: certInfo.serialNumber || 'Unknown',
      selfSigned: checks.selfSigned,
      signatureAlgorithm: certInfo.signatureAlgorithm || 'Unknown',
      publicKeyInfo: getPublicKeyInfo(cert),
      authorized: checks.authorized,
      validChain: checks.validChain,
      issuerChain: checks.validChain ? 'Complete' : 'Incomplete'
    };

  } catch (error) {
    console.error('SSL Certificate check error:', error);
    return createDefaultResponse('Error checking SSL certificate');
  }
}

function createDefaultResponse(details: string) {
  return {
    status: 'vulnerable',
    details,
    issuer: 'Unknown',
    subject: 'Unknown',
    validFrom: 'Unknown',
    validTo: 'Unknown',
    serialNumber: 'Unknown',
    selfSigned: false,
    signatureAlgorithm: 'Unknown',
    publicKeyInfo: 'Unknown',
    authorized: false,
    validChain: false,
    issuerChain: 'Unknown'
  };
}

function extractIssuer(cert: DetailedPeerCertificate): string {
  if (!cert.issuer) return 'Unknown';
  
  return cert.issuer.O || // Organization
         cert.issuer.CN || // Common Name
         cert.issuer.organizationName ||
         Object.values(cert.issuer).join(', ') ||
         'Unknown';
}

function extractSubject(cert: DetailedPeerCertificate): string {
  if (!cert.subject) return 'Unknown';
  
  return cert.subject.CN || // Common Name
         cert.subject.O || // Organization
         cert.subject.commonName ||
         Object.values(cert.subject).join(', ') ||
         'Unknown';
}

function isSelfSigned(cert: DetailedPeerCertificate): boolean {
  if (!cert.issuer || !cert.subject) return false;
  
  const issuerStr = JSON.stringify(cert.issuer);
  const subjectStr = JSON.stringify(cert.subject);
  
  return issuerStr === subjectStr;
}

function hasValidChain(cert: DetailedPeerCertificate): boolean {
  return 'issuerCertificate' in cert && 
         cert.issuerCertificate !== cert && // Not self-signed
         Object.keys(cert.issuerCertificate || {}).length > 0;
}

function getPublicKeyInfo(cert: DetailedPeerCertificate): string {
  const bits = (cert as any).bits;
  const type = cert.publicKey?.type || 'Unknown';
  
  if (!bits) return 'Unknown';
  return `${bits}-bit ${type}`;
}

function checkSQLInjection(data: string) {
  // Common SQL error messages and patterns
  const sqlErrors = [
    // MySQL errors
    'sql syntax',
    'mysql_fetch_array',
    'mysql_fetch_assoc',
    'mysql_num_rows',
    'mysql error',
    'you have an error in your sql syntax',
    'warning: mysql',
    'unclosed quotation mark',
    'quoted string not properly terminated',
    'mysql_query',
    'mysqli_query',
    'mysql_db_query',
    'access denied for user',
    'connection refused',
    
    // PostgreSQL errors
    'psql error',
    'postgresql error',
    'pg_query',
    'pg_exec',
    'pg_execute',
    
    // SQL Server errors
    'sql server error',
    'odbc error',
    'driver error',
    'oledb error',
    'sqlsrv_query',
    'mssql_query',
    'microsoft ole db provider for sql server',
    'unclosed quotation mark after the character string',
    
    // Oracle errors
    'ora-',
    'oracle error',
    'oci_execute',
    'ociexecute',
    'ora-01756',
    'ora-00936',
    'ora-00921',
    
    // SQLite errors
    'sqlite_error',
    'sqlite3::',
    'sqlite_query',
    
    // Generic SQL patterns
    'sql error',
    'invalid query',
    'database error',
    'query failed',
    'syntax error',
    'incorrect syntax',
    'unexpected end of sql command',
    'unterminated string',
    'error in your sql syntax',
  ]

  // Form input patterns that might be vulnerable
  const formInputPatterns = [
    '<input[^>]*name=["\'].*(?:id|user|username|password|query|search|keyword|email|login)["\'][^>]*>',
    '<form[^>]*action=["\'][^"\']*(?:search|query|login|authenticate|admin|user)[^"\']*["\'][^>]*>',
    '<input[^>]*type=["\'](?:text|search)["\'][^>]*>',
    'method=["\'](?:post|get)["\']',
  ]

  // Common vulnerable parameters in URLs
  const vulnerableParams = [
    'id=',
    'userid=',
    'username=',
    'password=',
    'query=',
    'search=',
    'category=',
    'article=',
    'page=',
    'user=',
    'email=',
    'login=',
    'admin=',
    'uid=',
    'pid=',
    'cid=',
    'sid=',
  ]

  // Database interaction patterns
  const databasePatterns = [
    'select+from',
    'insert+into',
    'update+set',
    'delete+from',
    'union+select',
    'union+all+select',
    'where+',
    'group+by',
    'order+by',
    'having+',
    'select%20',
    'union%20',
    'from%20',
    'where%20',
    '1=1',
    '1=2',
    'or+1=1',
    'or+1=2',
    '--+',
    ';--',
    '/*',
    '*/',
    'waitfor+delay',
    'sleep(',
    'benchmark(',
  ]

  // Convert data to lowercase for case-insensitive matching
  const lowerData = data.toLowerCase()

  // Check for SQL error messages
  const hasErrorMessages = sqlErrors.some(error => 
    lowerData.includes(error.toLowerCase())
  )

  // Check for potentially vulnerable form inputs
  const hasVulnerableInputs = formInputPatterns.some(pattern => 
    new RegExp(pattern, 'i').test(data)
  )

  // Check for vulnerable URL parameters
  const hasVulnerableParams = vulnerableParams.some(param => 
    lowerData.includes(param.toLowerCase())
  )

  // Check for direct database interaction patterns
  const hasDatabasePatterns = databasePatterns.some(pattern => 
    lowerData.includes(pattern.toLowerCase())
  )

  // Additional checks for common injection points
  const hasLoginForm = /<form[^>]*login[^>]*>/i.test(data)
  const hasSearchForm = /<form[^>]*search[^>]*>/i.test(data)
  const hasAdminSection = /admin/i.test(data)

  // Calculate vulnerability score (0-100)
  let vulnerabilityScore = 0
  if (hasErrorMessages) vulnerabilityScore += 40
  if (hasVulnerableInputs) vulnerabilityScore += 20
  if (hasVulnerableParams) vulnerabilityScore += 20
  if (hasDatabasePatterns) vulnerabilityScore += 20
  if (hasLoginForm) vulnerabilityScore += 10
  if (hasSearchForm) vulnerabilityScore += 10
  if (hasAdminSection) vulnerabilityScore += 10

  // Determine status based on vulnerability score
  const isVulnerable = vulnerabilityScore >= 30

  // Collect all detected issues
  const issues = []
  if (hasErrorMessages) issues.push('SQL error messages exposed')
  if (hasVulnerableInputs) issues.push('Potentially vulnerable form inputs detected')
  if (hasVulnerableParams) issues.push('Vulnerable URL parameters found')
  if (hasDatabasePatterns) issues.push('Direct database query patterns detected')
  if (hasLoginForm) issues.push('Login form detected')
  if (hasSearchForm) issues.push('Search form detected')
  if (hasAdminSection) issues.push('Admin section detected')

  return {
    status: isVulnerable ? 'vulnerable' : 'secure',
    details: isVulnerable 
      ? `Potential SQL injection vulnerabilities detected: ${issues.join(', ')}`
      : 'No obvious SQL injection vulnerabilities found',
    vulnerabilityLevel: vulnerabilityScore,
    technicalDetails: {
      hasErrorMessages,
      hasVulnerableInputs,
      hasVulnerableParams,
      hasDatabasePatterns,
      hasLoginForm,
      hasSearchForm,
      hasAdminSection,
      vulnerabilityScore,
      detectedIssues: issues
    }
  }
}

function checkXSS(data: string) {
  try {
    const dom = new JSDOM(data)
    const document = dom.window.document

    // Dangerous patterns to check
    const dangerousPatterns = {
      scripts: {
        elements: Array.from(document.querySelectorAll('script')),
        patterns: [
          'document.cookie',
          'document.write',
          'document.location',
          'localStorage',
          'sessionStorage',
          'window.location',
          'eval(',
          'setTimeout(',
          'setInterval(',
          'innerHTML',
          'outerHTML',
          'alert(',
          'prompt(',
          'confirm(',
          'execScript(',
          'Function(',
          'fetch(',
          'XMLHttpRequest',
          'WebSocket',
          'prototype',
          'constructor'
        ]
      },
      attributes: {
        dangerous: [
          'onload',
          'onerror',
          'onmouseover',
          'onclick',
          'onmouseout',
          'onkeypress',
          'onsubmit',
          'onmouseenter',
          'onchange',
          'onfocus',
          'onblur',
          'oncut',
          'oncopy',
          'onpaste',
          'ondrag',
          'ondrop',
          'onkeyup',
          'onkeydown'
        ]
      },
      inputs: {
        elements: Array.from(document.querySelectorAll('input, textarea')),
        attributes: ['type', 'name', 'value', 'placeholder']
      },
      links: {
        elements: Array.from(document.querySelectorAll('a')),
        attributes: ['href', 'onclick']
      },
      forms: {
        elements: Array.from(document.querySelectorAll('form')),
        attributes: ['action', 'onsubmit']
      },
      iframes: {
        elements: Array.from(document.querySelectorAll('iframe')),
        attributes: ['src', 'srcdoc']
      }
    }

    // Initialize findings
    const findings = {
      dangerousScripts: [] as string[],
      unsafeEventHandlers: [] as string[],
      reflectedParameters: [] as string[],
      unsafeLinks: [] as string[],
      unsafeIframes: [] as string[],
      vulnerableInputs: [] as string[],
      unsanitizedData: [] as string[]
    }

    // Check scripts
    dangerousPatterns.scripts.elements.forEach(script => {
      const content = script.textContent?.toLowerCase() || ''
      dangerousPatterns.scripts.patterns.forEach(pattern => {
        if (content.includes(pattern.toLowerCase())) {
          findings.dangerousScripts.push(`Potentially dangerous script containing "${pattern}"`)
        }
      })
    })

    // Check for unsafe event handlers on all elements
    const allElements = Array.from(document.querySelectorAll('*'))
    allElements.forEach(element => {
      const attributes = Array.from(element.attributes || [])
      attributes.forEach(attr => {
        if (dangerousPatterns.attributes.dangerous.includes(attr.name.toLowerCase())) {
          findings.unsafeEventHandlers.push(
            `Unsafe event handler "${attr.name}" found on ${element.tagName.toLowerCase()}`
          )
        }
      })
    })

    // Check for reflected parameters in URL and response
    const urlParams = new URLSearchParams(data.split('?')[1] || '')
    urlParams.forEach((value, param) => {
      if (data.includes(value)) {
        findings.reflectedParameters.push(`Parameter "${param}" is reflected in the response`)
      }
    })

    // Check for unsafe links
    dangerousPatterns.links.elements.forEach(link => {
      const href = link.getAttribute('href')
      if (href?.toLowerCase().includes('javascript:')) {
        findings.unsafeLinks.push(`Unsafe JavaScript URL found: ${href}`)
      }
    })

    // Check for unsafe iframes
    dangerousPatterns.iframes.elements.forEach(iframe => {
      if (!iframe.getAttribute('sandbox')) {
        findings.unsafeIframes.push('Iframe without sandbox attribute detected')
      }
    })

    // Check for vulnerable inputs
    dangerousPatterns.inputs.elements.forEach(input => {
      const type = input.getAttribute('type')?.toLowerCase()
      if (!type || type === 'text') {
        if (!input.hasAttribute('maxlength')) {
          findings.vulnerableInputs.push('Input field without length restriction')
        }
      }
    })

    // Check for potentially unsanitized data
    const htmlComments = data.match(/<!--[\s\S]*?-->/g) || []
    htmlComments.forEach(comment => {
      if (comment.includes('<') && comment.includes('>')) {
        findings.unsanitizedData.push('HTML code found in comments')
      }
    })

    // Calculate vulnerability score
    let vulnerabilityScore = 0
    if (findings.dangerousScripts.length > 0) vulnerabilityScore += 30
    if (findings.unsafeEventHandlers.length > 0) vulnerabilityScore += 25
    if (findings.reflectedParameters.length > 0) vulnerabilityScore += 20
    if (findings.unsafeLinks.length > 0) vulnerabilityScore += 15
    if (findings.unsafeIframes.length > 0) vulnerabilityScore += 10
    if (findings.vulnerableInputs.length > 0) vulnerabilityScore += 10
    if (findings.unsanitizedData.length > 0) vulnerabilityScore += 10

    // Compile all findings
    const allFindings = [
      ...findings.dangerousScripts,
      ...findings.unsafeEventHandlers,
      ...findings.reflectedParameters,
      ...findings.unsafeLinks,
      ...findings.unsafeIframes,
      ...findings.vulnerableInputs,
      ...findings.unsanitizedData
    ]

    const isVulnerable = vulnerabilityScore >= 30

    return {
      status: isVulnerable ? 'vulnerable' : 'secure',
      details: isVulnerable 
        ? `Potential XSS vulnerabilities detected: ${allFindings.length} issues found`
        : 'No obvious XSS vulnerabilities found',
      vulnerabilityLevel: vulnerabilityScore,
      technicalDetails: {
        findings: allFindings,
        vulnerabilityScore,
        dangerousScripts: findings.dangerousScripts.length,
        unsafeEventHandlers: findings.unsafeEventHandlers.length,
        reflectedParameters: findings.reflectedParameters.length,
        unsafeLinks: findings.unsafeLinks.length,
        unsafeIframes: findings.unsafeIframes.length,
        vulnerableInputs: findings.vulnerableInputs.length,
        unsanitizedData: findings.unsanitizedData.length
      }
    }
  } catch (error) {
    console.error('XSS check error:', error)
    return {
      status: 'error',
      details: 'Error checking for XSS vulnerabilities',
      vulnerabilityLevel: 0,
      technicalDetails: {
        error: 'Failed to analyze page for XSS vulnerabilities'
      }
    }
  }
}

function checkHTTPHeaders(headers: Record<string, string | string[]>) {
  // Security headers to check with their importance level (1-3)
  const securityHeaders = {
    'Strict-Transport-Security': {
      level: 3,
      description: 'Enforces HTTPS connections'
    },
    'Content-Security-Policy': {
      level: 3,
      description: 'Controls resources the browser is allowed to load'
    },
    'X-Frame-Options': {
      level: 2,
      description: 'Prevents clickjacking attacks'
    },
    'X-XSS-Protection': {
      level: 2,
      description: 'Enables browser XSS filtering'
    },
    'X-Content-Type-Options': {
      level: 2,
      description: 'Prevents MIME-type sniffing'
    },
    'Referrer-Policy': {
      level: 2,
      description: 'Controls referrer information'
    },
    'Permissions-Policy': {
      level: 2,
      description: 'Controls browser features and APIs'
    },
    'Access-Control-Allow-Origin': {
      level: 2,
      description: 'Controls cross-origin resource sharing'
    },
    'X-Permitted-Cross-Domain-Policies': {
      level: 1,
      description: 'Controls cross-domain policies'
    },
    'Cross-Origin-Opener-Policy': {
      level: 1,
      description: 'Controls cross-origin window interactions'
    },
    'Cross-Origin-Resource-Policy': {
      level: 1,
      description: 'Controls cross-origin resource sharing'
    },
    'Cross-Origin-Embedder-Policy': {
      level: 1,
      description: 'Controls cross-origin embedding'
    }
  };

  // Initialize findings
  const findings = {
    presentHeaders: [] as string[],
    missingHeaders: [] as string[],
    weakHeaders: [] as string[],
    headerDetails: [] as { header: string; status: string; description: string; value?: string }[]
  };

  // Check each security header
  Object.entries(securityHeaders).forEach(([header, info]) => {
    const headerValue = headers[header.toLowerCase()];
    
    if (!headerValue) {
      findings.missingHeaders.push(header);
      findings.headerDetails.push({
        header,
        status: 'Missing',
        description: info.description
      });
    } else {
      findings.presentHeaders.push(header);
      findings.headerDetails.push({
        header,
        status: 'Present',
        description: info.description,
        value: Array.isArray(headerValue) ? headerValue.join(', ') : headerValue
      });

      // Check for weak configurations
      if (header === 'X-Frame-Options' && 
          !['DENY', 'SAMEORIGIN'].includes(String(headerValue).toUpperCase())) {
        findings.weakHeaders.push(`${header} (Weak configuration)`);
      }
      if (header === 'X-XSS-Protection' && 
          !['1; mode=block'].includes(String(headerValue))) {
        findings.weakHeaders.push(`${header} (Weak configuration)`);
      }
    }
  });

  // Calculate vulnerability score
  let totalWeight = 0;
  let secureWeight = 0;

  Object.entries(securityHeaders).forEach(([header, info]) => {
    const weight = info.level;
    totalWeight += weight;
    
    if (findings.presentHeaders.includes(header) && 
        !findings.weakHeaders.find(h => h.startsWith(header))) {
      secureWeight += weight;
    }
  });

  const vulnerabilityScore = Math.round((1 - (secureWeight / totalWeight)) * 100);
  const isVulnerable = vulnerabilityScore > 30;

  // Generate detailed report
  const details = isVulnerable
    ? `Missing ${findings.missingHeaders.length} security headers, ${findings.weakHeaders.length} weak configurations`
    : 'Security headers are properly configured';

  return {
    status: isVulnerable ? 'vulnerable' : 'secure',
    details,
    vulnerabilityLevel: vulnerabilityScore,
    technicalDetails: {
      presentHeaders: findings.presentHeaders,
      missingHeaders: findings.missingHeaders,
      weakHeaders: findings.weakHeaders,
      headerDetails: findings.headerDetails,
      vulnerabilityScore,
      totalHeadersChecked: Object.keys(securityHeaders).length,
      presentHeadersCount: findings.presentHeaders.length,
      missingHeadersCount: findings.missingHeaders.length,
      weakHeadersCount: findings.weakHeaders.length
    }
  };
}

function checkOpenRedirect(data: string) {
  const dom = new JSDOM(data)
  const anchors = dom.window.document.querySelectorAll('a')
  const suspiciousLinks = Array.from(anchors).filter(anchor => {
    const href = anchor.getAttribute('href')
    return href && href.startsWith('http') && !href.includes('example.com') // Example condition, adjust based on target domain
  })

  return {
    status: suspiciousLinks.length > 0 ? 'vulnerable' : 'secure',
    details: suspiciousLinks.length > 0 ? 'Potential open redirect vulnerability detected' : 'No obvious open redirect vulnerabilities found',
  }
}

function checkCSRF(data: string, headers: Record<string, string | string[]>) {
  try {
    const dom = new JSDOM(data)
    const document = dom.window.document

    // Initialize findings
    const findings = {
      missingCSRFToken: false,
      unsecuredForms: [] as string[],
      missingHeaders: [] as string[],
      weakConfiguration: [] as string[],
      vulnerableEndpoints: [] as string[]
    }

    // Check security headers
    const csrfHeaders = [
      'X-CSRF-Token',
      'CSRF-Token',
      'X-XSRF-Token',
      'X-CSRFToken',
      'Anti-CSRF-Token',
      'X-Anti-Forgery-Token'
    ]

    const hasCSRFHeader = csrfHeaders.some(header => 
      headers[header.toLowerCase()] !== undefined
    )

    if (!hasCSRFHeader) {
      findings.missingHeaders.push('No CSRF protection headers found')
    }

    // Check forms for CSRF tokens
    const forms = Array.from(document.querySelectorAll('form'))
    forms.forEach(form => {
      const method = form.getAttribute('method')?.toLowerCase()
      if (method === 'post' || method === 'put' || method === 'delete') {
        const hasCSRFToken = Array.from(form.elements).some(element => {
          const input = element as HTMLInputElement
          const name = input.name?.toLowerCase()
          return name?.includes('csrf') || 
                 name?.includes('token') || 
                 name?.includes('xsrf') ||
                 input.getAttribute('data-csrf') !== null
        })

        if (!hasCSRFToken) {
          findings.unsecuredForms.push(
            `Form with action "${form.action || 'unknown'}" missing CSRF token`
          )
        }
      }
    })

    // Check for SameSite cookie attribute
    const cookieHeader = headers['set-cookie']
    if (cookieHeader) {
      const cookies = Array.isArray(cookieHeader) ? cookieHeader : [cookieHeader]
      const hasWeakSameSite = cookies.some(cookie => 
        !cookie.toLowerCase().includes('samesite=strict') &&
        !cookie.toLowerCase().includes('samesite=lax')
      )

      if (hasWeakSameSite) {
        findings.weakConfiguration.push('Cookies missing or have weak SameSite attribute')
      }
    }

    // Check for potentially vulnerable endpoints
    const links = Array.from(document.querySelectorAll('a'))
    links.forEach(link => {
      const href = link.getAttribute('href')
      if (href?.includes('/api/') || 
          href?.includes('/admin/') || 
          href?.includes('/dashboard/')) {
        findings.vulnerableEndpoints.push(
          `Potentially vulnerable endpoint: ${href}`
        )
      }
    })

    // Calculate vulnerability score
    let vulnerabilityScore = 0
    if (findings.missingHeaders.length > 0) vulnerabilityScore += 30
    if (findings.unsecuredForms.length > 0) vulnerabilityScore += 25
    if (findings.weakConfiguration.length > 0) vulnerabilityScore += 25
    if (findings.vulnerableEndpoints.length > 0) vulnerabilityScore += 20

    // Compile all findings
    const allFindings = [
      ...findings.missingHeaders,
      ...findings.unsecuredForms,
      ...findings.weakConfiguration,
      ...findings.vulnerableEndpoints
    ]

    const isVulnerable = vulnerabilityScore >= 30

    return {
      status: isVulnerable ? 'vulnerable' : 'secure',
      details: isVulnerable 
        ? `CSRF vulnerabilities detected: ${allFindings.length} issues found`
        : 'No obvious CSRF vulnerabilities found',
      vulnerabilityLevel: vulnerabilityScore,
      technicalDetails: {
        findings: allFindings,
        vulnerabilityScore,
        missingHeaders: findings.missingHeaders,
        unsecuredForms: findings.unsecuredForms,
        weakConfiguration: findings.weakConfiguration,
        vulnerableEndpoints: findings.vulnerableEndpoints,
        totalIssues: allFindings.length
      }
    }
  } catch (error) {
    console.error('CSRF check error:', error)
    return {
      status: 'error',
      details: 'Error checking for CSRF vulnerabilities',
      vulnerabilityLevel: 0,
      technicalDetails: {
        error: 'Failed to analyze page for CSRF vulnerabilities'
      }
    }
  }
}

function checkSSRF(data: string) {
  try {
    const dom = new JSDOM(data)
    const document = dom.window.document

    // Initialize findings
    const findings = {
      vulnerableUrls: [] as string[],
      vulnerableInputs: [] as string[],
      vulnerableEndpoints: [] as string[],
      riskPatterns: [] as string[],
      dynamicRequests: [] as string[]
    }

    // Check for URL input fields with potential SSRF risks
    const urlInputs = Array.from(document.querySelectorAll('input[type="url"], input[name*="url"], input[name*="link"], input[name*="file"], input[name*="path"]'))
    urlInputs.forEach(input => {
      const inputName = (input as HTMLInputElement).name || '';
      const inputId = (input as HTMLInputElement).id || '';
      if (
        inputName.toLowerCase().includes('url') ||
        inputName.toLowerCase().includes('link') ||
        inputName.toLowerCase().includes('file') ||
        inputName.toLowerCase().includes('path') ||
        inputId.toLowerCase().includes('url') ||
        inputId.toLowerCase().includes('link')
      ) {
        findings.vulnerableInputs.push(`Potentially vulnerable URL input field: ${inputName || inputId}`)
      }
    })

    // Check for forms with URL-related actions or file uploads
    const forms = Array.from(document.querySelectorAll('form'))
    forms.forEach(form => {
      const action = form.getAttribute('action')?.toLowerCase() || ''
      const method = form.getAttribute('method')?.toLowerCase() || ''
      
      if (
        action.includes('url=') ||
        action.includes('link=') ||
        action.includes('path=') ||
        action.includes('file=') ||
        action.includes('load=') ||
        action.includes('fetch=') ||
        action.includes('download=')
      ) {
        findings.vulnerableEndpoints.push(`Form with potentially vulnerable action: ${action}`)
      }

      // Check for file upload forms
      const hasFileInput = Array.from(form.elements).some(
        element => (element as HTMLInputElement).type === 'file'
      )
      if (hasFileInput && method === 'post') {
        findings.vulnerableEndpoints.push(`File upload form detected: ${action}`)
      }
    })

    // Enhanced list of risky URL patterns
    const riskPatterns = [
      'file://',
      'gopher://',
      'dict://',
      'ldap://',
      'ftp://',
      'tftp://',
      'php://',
      'jar://',
      'data:',
      'localhost',
      '127.0.0.1',
      '0.0.0.0',
      'internal.',
      'private.',
      'local.',
      '.local',
      '.internal',
      '.localhost',
      'docker.',
      'kubernetes.',
      'meta-data',
      '169.254.169.254',
      '::1',
      'ec2.',
      'amazonaws.com',
      'metadata.',
      'instance-data'
    ]

    // Check scripts for dynamic URL handling
    const scripts = Array.from(document.querySelectorAll('script'))
    scripts.forEach(script => {
      const content = script.textContent?.toLowerCase() || ''
      if (
        content.includes('fetch(') ||
        content.includes('xhr.open(') ||
        content.includes('axios.get(') ||
        content.includes('$.ajax') ||
        content.includes('new image(') ||
        content.includes('xmlhttprequest')
      ) {
        findings.dynamicRequests.push('Dynamic URL request detected in JavaScript')
      }
    })

    // Check all elements with URLs
    const elements = Array.from(document.querySelectorAll(
      'a[href], img[src], script[src], iframe[src], embed[src], object[data], link[href], video[src], audio[src], source[src]'
    ))
    
    elements.forEach(element => {
      const url = element.getAttribute('href') || 
                 element.getAttribute('src') || 
                 element.getAttribute('data') || ''
      
      riskPatterns.forEach(pattern => {
        if (url.toLowerCase().includes(pattern)) {
          findings.riskPatterns.push(`Found risky URL pattern "${pattern}" in: ${url}`)
        }
      })

      // Check for URL parameters that might lead to SSRF
      if (url.includes('?')) {
        const params = new URLSearchParams(url.split('?')[1])
        params.forEach((value, key) => {
          if (
            key.toLowerCase().includes('url') ||
            key.toLowerCase().includes('link') ||
            key.toLowerCase().includes('path') ||
            key.toLowerCase().includes('file') ||
            key.toLowerCase().includes('load')
          ) {
            findings.vulnerableUrls.push(`Potentially vulnerable URL parameter: ${key}=${value}`)
          }
        })
      }
    })

    // Calculate vulnerability score with weighted factors
    let vulnerabilityScore = 0
    
    // High-risk findings (30 points each)
    if (findings.riskPatterns.length > 0) vulnerabilityScore += 30
    
    // Medium-risk findings (20 points each)
    if (findings.vulnerableEndpoints.length > 0) vulnerabilityScore += 20
    if (findings.dynamicRequests.length > 0) vulnerabilityScore += 20
    
    // Lower-risk findings (15 points each)
    if (findings.vulnerableUrls.length > 0) vulnerabilityScore += 15
    if (findings.vulnerableInputs.length > 0) vulnerabilityScore += 15

    // Additional points for multiple findings
    vulnerabilityScore += Math.min(20, (
      findings.riskPatterns.length +
      findings.vulnerableEndpoints.length +
      findings.vulnerableUrls.length +
      findings.vulnerableInputs.length +
      findings.dynamicRequests.length
    ) * 2)

    // Cap the score at 100
    vulnerabilityScore = Math.min(100, vulnerabilityScore)

    // Compile all findings
    const allFindings = [
      ...findings.vulnerableUrls,
      ...findings.vulnerableInputs,
      ...findings.vulnerableEndpoints,
      ...findings.riskPatterns,
      ...findings.dynamicRequests
    ]

    const isVulnerable = vulnerabilityScore >= 30

    return {
      status: isVulnerable ? 'vulnerable' : 'secure',
      details: isVulnerable 
        ? `SSRF vulnerabilities detected: ${allFindings.length} issues found`
        : 'No obvious SSRF vulnerabilities found',
      vulnerabilityLevel: vulnerabilityScore,
      technicalDetails: {
        findings: allFindings,
        vulnerabilityScore,
        vulnerableUrls: findings.vulnerableUrls,
        vulnerableInputs: findings.vulnerableInputs,
        vulnerableEndpoints: findings.vulnerableEndpoints,
        riskPatterns: findings.riskPatterns,
        dynamicRequests: findings.dynamicRequests,
        totalIssues: allFindings.length
      }
    }
  } catch (error) {
    console.error('SSRF check error:', error)
    return {
      status: 'error',
      details: 'Error checking for SSRF vulnerabilities',
      vulnerabilityLevel: 0,
      technicalDetails: {
        error: 'Failed to analyze page for SSRF vulnerabilities'
      }
    }
  }
}

function checkIDOR(data: string) {
  try {
    const dom = new JSDOM(data)
    const document = dom.window.document

    // Initialize findings
    const findings = {
      exposedIds: [] as string[],
      vulnerableEndpoints: [] as string[],
      vulnerableParameters: [] as string[],
      predictablePatterns: [] as string[],
      accessControls: [] as string[]
    }

    // Check for exposed IDs in URLs and links
    const links = Array.from(document.querySelectorAll('a[href]'))
    links.forEach(link => {
      const href = link.getAttribute('href')
      if (href) {
        // Check for numeric IDs in URLs
        const numericIdPattern = /[?&/](id|user_id|account|profile|order|item)=?\d+/i
        const matches = href.match(numericIdPattern)
        if (matches) {
          findings.exposedIds.push(`Exposed numeric ID in URL: ${matches[0]}`)
        }

        // Check for UUID/GUID patterns
        const uuidPattern = /[?&/][a-f\d]{8}(-[a-f\d]{4}){3}-[a-f\d]{12}/i
        const uuidMatches = href.match(uuidPattern)
        if (uuidMatches) {
          findings.exposedIds.push(`Exposed UUID in URL: ${uuidMatches[0]}`)
        }

        // Check for sequential or predictable IDs
        const sequentialPattern = /[?&/](id|user|account)=?\d{1,4}$/i
        if (sequentialPattern.test(href)) {
          findings.predictablePatterns.push(`Potentially sequential ID: ${href}`)
        }
      }
    })

    // Check for forms with ID parameters
    const forms = Array.from(document.querySelectorAll('form'))
    forms.forEach(form => {
      const action = form.getAttribute('action')
      const method = form.getAttribute('method')?.toUpperCase()
      
      if (action) {
        // Check for ID parameters in form actions
        if (/[?&](id|user_id|account|profile)=/i.test(action)) {
          findings.vulnerableEndpoints.push(`Form endpoint with ID parameter: ${action}`)
        }

        // Check for PUT/DELETE methods without proper authorization checks
        if (method === 'PUT' || method === 'DELETE') {
          findings.accessControls.push(`${method} method used in form: ${action}`)
        }
      }

      // Check for hidden fields containing IDs
      const hiddenFields = Array.from(form.querySelectorAll('input[type="hidden"]'))
      hiddenFields.forEach(field => {
        const name = (field as HTMLInputElement).name
        const value = (field as HTMLInputElement).value
        if (/id|user|account/i.test(name) && value) {
          findings.exposedIds.push(`Hidden field with ID: ${name}=${value}`)
        }
      })
    })

    // Check for API endpoints
    const scripts = Array.from(document.querySelectorAll('script'))
    scripts.forEach(script => {
      const content = script.textContent || ''
      
      // Check for API endpoints with ID parameters
      const apiPattern = /\/api\/.*?\/\d+/g
      const apiMatches = content.match(apiPattern)
      if (apiMatches) {
        findings.vulnerableEndpoints.push(...apiMatches.map(match => 
          `API endpoint with numeric ID: ${match}`
        ))
      }

      // Check for direct object references in JavaScript
      const objectPattern = /(get|post|put|delete).*?['"]([/].*?[/]\d+)['"]*/gi;
      const objectMatches = Array.from(content.matchAll(objectPattern) || []);
      objectMatches.forEach(match => {
        findings.vulnerableEndpoints.push(
          `Direct object reference in JavaScript: ${match[1].toUpperCase()} ${match[2]}`
        );
      });
    })

    // Check URL parameters
    const urlParams = new URLSearchParams(data.split('?')[1] || '')
    urlParams.forEach((value, key) => {
      if (/id|user|account|profile|order/i.test(key)) {
        findings.vulnerableParameters.push(`URL parameter with potential IDOR: ${key}=${value}`)
      }
    })

    // Calculate vulnerability score
    let vulnerabilityScore = 0
    
    // High-risk findings (30 points each)
    if (findings.exposedIds.length > 0) vulnerabilityScore += 30
    if (findings.vulnerableEndpoints.length > 0) vulnerabilityScore += 30
    
    // Medium-risk findings (20 points each)
    if (findings.predictablePatterns.length > 0) vulnerabilityScore += 20
    if (findings.accessControls.length > 0) vulnerabilityScore += 20
    
    // Lower-risk findings (15 points each)
    if (findings.vulnerableParameters.length > 0) vulnerabilityScore += 15

    // Additional points for multiple findings
    vulnerabilityScore += Math.min(20, (
      findings.exposedIds.length +
      findings.vulnerableEndpoints.length +
      findings.predictablePatterns.length +
      findings.accessControls.length +
      findings.vulnerableParameters.length
    ) * 2)

    // Cap the score at 100
    vulnerabilityScore = Math.min(100, vulnerabilityScore)

    // Compile all findings
    const allFindings = [
      ...findings.exposedIds,
      ...findings.vulnerableEndpoints,
      ...findings.vulnerableParameters,
      ...findings.predictablePatterns,
      ...findings.accessControls
    ]

    const isVulnerable = vulnerabilityScore >= 30

    return {
      status: isVulnerable ? 'vulnerable' : 'secure',
      details: isVulnerable 
        ? `IDOR vulnerabilities detected: ${allFindings.length} issues found`
        : 'No obvious IDOR vulnerabilities found',
      vulnerabilityLevel: vulnerabilityScore,
      technicalDetails: {
        findings: allFindings,
        vulnerabilityScore,
        exposedIds: findings.exposedIds,
        vulnerableEndpoints: findings.vulnerableEndpoints,
        vulnerableParameters: findings.vulnerableParameters,
        predictablePatterns: findings.predictablePatterns,
        accessControls: findings.accessControls,
        totalIssues: allFindings.length
      }
    }
  } catch (error) {
    console.error('IDOR check error:', error)
    return {
      status: 'error',
      details: 'Error checking for IDOR vulnerabilities',
      vulnerabilityLevel: 0,
      technicalDetails: {
        error: 'Failed to analyze page for IDOR vulnerabilities'
      }
    }
  }
}

function checkLDAP(data: string) {
  try {
    const dom = new JSDOM(data)
    const document = dom.window.document

    // Initialize findings
    const findings = {
      vulnerableInputs: [] as string[],
      vulnerableEndpoints: [] as string[],
      suspiciousPatterns: [] as string[],
      authenticationForms: [] as string[],
      directoryPatterns: [] as string[]
    }

    // LDAP injection patterns
    const ldapPatterns = [
      '*)(uid=*',
      '*)(cn=*',
      '*)(sn=*',
      '*)(dn=*',
      '*)(objectClass=*',
      '*)(mail=*',
      '*)(&',
      '*)(|',
      '*))%00',
      '*))\\00',
      '*)(!',
      '*)(distinguishedName=*',
      '*)(userPassword=*',
      '*)(memberOf=*',
      '*)(&(&',
      '*)(|(|',
      '*)(!(!'
    ]

    // Check for LDAP-related input fields
    const inputs = Array.from(document.querySelectorAll('input'))
    inputs.forEach(input => {
      const inputName = (input as HTMLInputElement).name?.toLowerCase() || ''
      const inputId = (input as HTMLInputElement).id?.toLowerCase() || ''
      const inputType = (input as HTMLInputElement).type?.toLowerCase() || ''

      if (
        inputName.includes('user') ||
        inputName.includes('username') ||
        inputName.includes('uid') ||
        inputName.includes('cn') ||
        inputName.includes('dn') ||
        inputName.includes('group') ||
        inputName.includes('ou') ||
        inputName.includes('dc') ||
        inputId.includes('ldap') ||
        inputType === 'text'
      ) {
        findings.vulnerableInputs.push(
          `Potentially vulnerable LDAP input field: ${inputName || inputId}`
        )
      }
    })

    // Check for authentication forms
    const forms = Array.from(document.querySelectorAll('form'))
    forms.forEach(form => {
      const action = form.getAttribute('action')?.toLowerCase() || ''
      const method = form.getAttribute('method')?.toLowerCase() || ''
      
      if (
        action.includes('auth') ||
        action.includes('login') ||
        action.includes('ldap') ||
        action.includes('directory') ||
        action.includes('authenticate')
      ) {
        findings.authenticationForms.push(
          `Authentication form detected: ${action}`
        )
      }

      // Check for hidden fields that might contain LDAP queries
      const hiddenFields = Array.from(form.querySelectorAll('input[type="hidden"]'))
      hiddenFields.forEach(field => {
        const value = (field as HTMLInputElement).value || ''
        if (value.includes('(') && value.includes(')')) {
          findings.suspiciousPatterns.push(
            `Hidden field with potential LDAP query: ${value}`
          )
        }
      })
    })

    // Check for LDAP-related endpoints
    const links = Array.from(document.querySelectorAll('a[href]'))
    links.forEach(link => {
      const href = link.getAttribute('href')
      if (href?.toLowerCase().includes('ldap') ||
          href?.toLowerCase().includes('directory') ||
          href?.toLowerCase().includes('auth')) {
        findings.vulnerableEndpoints.push(
          `Potential LDAP endpoint: ${href}`
        )
      }
    })

    // Check for directory structure patterns
    const directoryPatterns = [
      /dc=[\w-]+,dc=[\w-]+/i,
      /ou=[\w-]+,/i,
      /cn=[\w-]+,/i,
      /uid=[\w-]+,/i,
      /l=[\w-]+,/i,
      /o=[\w-]+,/i
    ]

    const content = document.documentElement.innerHTML
    directoryPatterns.forEach(pattern => {
      const matches = content.match(pattern)
      if (matches) {
        findings.directoryPatterns.push(
          `Directory structure pattern found: ${matches[0]}`
        )
      }
    })

    // Check scripts for LDAP-related code
    const scripts = Array.from(document.querySelectorAll('script'))
    scripts.forEach(script => {
      const content = script.textContent?.toLowerCase() || ''
      
      ldapPatterns.forEach(pattern => {
        if (content.includes(pattern)) {
          findings.suspiciousPatterns.push(
            `LDAP injection pattern found in script: ${pattern}`
          )
        }
      })

      if (
        content.includes('ldap') ||
        content.includes('activedirectory') ||
        content.includes('directory') ||
        content.includes('authenticate')
      ) {
        findings.suspiciousPatterns.push(
          'LDAP-related code found in JavaScript'
        )
      }
    })

    // Calculate vulnerability score
    let vulnerabilityScore = 0
    
    // High-risk findings (30 points each)
    if (findings.suspiciousPatterns.length > 0) vulnerabilityScore += 30
    if (findings.directoryPatterns.length > 0) vulnerabilityScore += 30
    
    // Medium-risk findings (20 points each)
    if (findings.vulnerableInputs.length > 0) vulnerabilityScore += 20
    if (findings.authenticationForms.length > 0) vulnerabilityScore += 20
    
    // Lower-risk findings (15 points each)
    if (findings.vulnerableEndpoints.length > 0) vulnerabilityScore += 15

    // Additional points for multiple findings
    vulnerabilityScore += Math.min(20, (
      findings.suspiciousPatterns.length +
      findings.directoryPatterns.length +
      findings.vulnerableInputs.length +
      findings.authenticationForms.length +
      findings.vulnerableEndpoints.length
    ) * 2)

    // Cap the score at 100
    vulnerabilityScore = Math.min(100, vulnerabilityScore)

    // Compile all findings
    const allFindings = [
      ...findings.vulnerableInputs,
      ...findings.vulnerableEndpoints,
      ...findings.suspiciousPatterns,
      ...findings.authenticationForms,
      ...findings.directoryPatterns
    ]

    const isVulnerable = vulnerabilityScore >= 30

    return {
      status: isVulnerable ? 'vulnerable' : 'secure',
      details: isVulnerable 
        ? `LDAP injection vulnerabilities detected: ${allFindings.length} issues found`
        : 'No obvious LDAP injection vulnerabilities found',
      vulnerabilityLevel: vulnerabilityScore,
      technicalDetails: {
        findings: allFindings,
        vulnerabilityScore,
        vulnerableInputs: findings.vulnerableInputs,
        vulnerableEndpoints: findings.vulnerableEndpoints,
        suspiciousPatterns: findings.suspiciousPatterns,
        authenticationForms: findings.authenticationForms,
        directoryPatterns: findings.directoryPatterns,
        totalIssues: allFindings.length
      }
    }
  } catch (error) {
    console.error('LDAP check error:', error)
    return {
      status: 'error',
      details: 'Error checking for LDAP injection vulnerabilities',
      vulnerabilityLevel: 0,
      technicalDetails: {
        error: 'Failed to analyze page for LDAP vulnerabilities'
      }
    }
  }
}

// Function to calculate overall score
function calculateOverallScore(results: any): number {
    const scores = [
        results.sslCertificate.status === 'secure' ? 100 : 0,
        results.sqlInjection.vulnerabilityLevel ? Math.max(0, 100 - results.sqlInjection.vulnerabilityLevel) : (results.sqlInjection.status === 'secure' ? 100 : 0),
        results.xss.technicalDetails?.vulnerabilityScore ? Math.max(0, 100 - results.xss.technicalDetails.vulnerabilityScore) : (results.xss.status === 'secure' ? 100 : 0),
        results.httpHeaders.vulnerabilityLevel ? Math.max(0, 100 - results.httpHeaders.vulnerabilityLevel) : (results.httpHeaders.status === 'secure' ? 100 : 0),
        results.csrf.vulnerabilityLevel ? Math.max(0, 100 - results.csrf.vulnerabilityLevel) : (results.csrf.status === 'secure' ? 100 : 0),
        results.ssrf.vulnerabilityLevel ? Math.max(0, 100 - results.ssrf.vulnerabilityLevel) : (results.ssrf.status === 'secure' ? 100 : 0),
        results.idor.vulnerabilityLevel ? Math.max(0, 100 - results.idor.vulnerabilityLevel) : (results.idor.status === 'secure' ? 100 : 0),
        results.ldap.vulnerabilityLevel ? Math.max(0, 100 - results.ldap.vulnerabilityLevel) : (results.ldap.status === 'secure' ? 100 : 0),
    ];

    // Filter out any undefined or null scores
    const validScores = scores.filter(score => score !== undefined && score !== null);

    // Calculate the average score
    const totalScore = validScores.reduce((acc, score) => acc + score, 0);
    return validScores.length > 0 ? totalScore / validScores.length : 0; // Return 0 if no valid scores
}
