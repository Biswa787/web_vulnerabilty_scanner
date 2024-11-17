'use client'

import { useState, useCallback, useEffect } from 'react'
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Loader2, AlertTriangle, CheckCircle, XCircle, Download, Trash2, Clock, Calendar, History, ArrowRight } from "lucide-react"
import Particles from "react-tsparticles"
import { loadSlim } from "tsparticles-slim"
import type { Container, Engine } from "tsparticles-engine"
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell, Area } from 'recharts'
import { motion } from "framer-motion";
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import html2canvas from 'html2canvas';
import { Progress } from "./components/ui/progress";
import LearningModule from "./components/LearningModule";

interface ScanResults {
  sslCertificate: {
    status: string;
    details: string;
    issuer?: string;
    subject?: string;
    validFrom?: string;
    validTo?: string;
    serialNumber?: string;
    selfSigned?: boolean;
    signatureAlgorithm?: string;
    publicKeyInfo?: string;
    authorized?: boolean;
    validChain?: boolean;
    issuerChain?: string;
  };
  sqlInjection: {
    status: string;
    details: string;
    vulnerabilityLevel?: number;
    technicalDetails?: {
      hasErrorMessages: boolean;
      hasVulnerableInputs: boolean;
      hasVulnerableParams: boolean;
      hasDatabasePatterns: boolean;
    };
  };
  xss: { status: string; details: string };
  httpHeaders: {
    status: string;
    details: string;
    vulnerabilityLevel?: number;
    technicalDetails?: {
      presentHeaders: string[];
      missingHeaders: string[];
      weakHeaders: string[];
      headerDetails: {
        header: string;
        status: string;
        description: string;
        value?: string;
      }[];
      vulnerabilityScore: number;
      totalHeadersChecked: number;
      presentHeadersCount: number;
      missingHeadersCount: number;
      weakHeadersCount: number;
    };
  };
  csrf: {
    status: string;
    details: string;
    vulnerabilityLevel?: number;
    technicalDetails?: {
      findings: string[];
      vulnerabilityScore: number;
      missingHeaders: string[];
      unsecuredForms: string[];
      weakConfiguration: string[];
      vulnerableEndpoints: string[];
      totalIssues: number;
    };
  };
  ssrf: {
    status: string;
    details: string;
    vulnerabilityLevel?: number;
    technicalDetails?: {
      findings: string[];
      vulnerabilityScore: number;
      vulnerableUrls: string[];
      vulnerableInputs: string[];
      vulnerableEndpoints: string[];
      riskPatterns: string[];
      totalIssues: number;
    };
  };
  idor: {
    status: string;
    details: string;
    vulnerabilityLevel?: number;
    technicalDetails?: {
      findings: string[];
      vulnerabilityScore: number;
      exposedIds: string[];
      vulnerableEndpoints: string[];
      vulnerableParameters: string[];
      predictablePatterns: string[];
      accessControls: string[];
      totalIssues: number;
    };
  };
  ldap: {
    status: string;
    details: string;
    vulnerabilityLevel?: number;
    technicalDetails?: {
      findings: string[];
      vulnerabilityScore: number;
      vulnerableInputs: string[];
      vulnerableEndpoints: string[];
      suspiciousPatterns: string[];
      authenticationForms: string[];
      directoryPatterns: string[];
      totalIssues: number;
    };
  };
  overallScore: number;
}

interface ScanHistory {
  url: string;
  timestamp: string;
  results: ScanResults;
}

const ScanningAnimation = () => (
  <div className="absolute inset-0 bg-black/20 backdrop-blur-sm flex items-center justify-center z-50">
    <div className="bg-white p-8 rounded-lg shadow-xl flex flex-col items-center space-y-4">
      <div className="relative w-24 h-24">
        <div className="absolute inset-0 border-4 border-blue-200 rounded-full"></div>
        <div className="absolute inset-0 border-4 border-blue-600 rounded-full animate-spin border-t-transparent"></div>
        <div className="absolute inset-2 border-4 border-blue-200 rounded-full"></div>
        <div className="absolute inset-2 border-4 border-blue-400 rounded-full animate-spin border-t-transparent" style={{ animationDirection: 'reverse' }}></div>
      </div>
      <div className="text-center">
        <h3 className="text-lg font-semibold text-gray-900">Scanning in Progress</h3>
        <p className="text-sm text-gray-500 mt-1">Analyzing security vulnerabilities...</p>
      </div>
      <div className="flex flex-col items-center space-y-2 text-sm text-gray-500">
        <div className="flex items-center space-x-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>Checking SSL Certificate</span>
        </div>
        <div className="flex items-center space-x-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>Testing SQL Injection</span>
        </div>
        <div className="flex items-center space-x-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>Analyzing XSS Vulnerabilities</span>
        </div>
        <div className="flex items-center space-x-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span>Verifying HTTP Headers</span>
        </div>
      </div>
    </div>
  </div>
);

// Define learning content
const learningContent = {
    sslCertificate: {
        title: "SSL Certificate Vulnerabilities",
        description: "SSL certificates are essential for establishing secure connections. Vulnerabilities can arise from misconfigurations or expired certificates.",
        examples: [
            "Using self-signed certificates in production.",
            "Certificates that have expired or are not trusted."
        ],
        resources: [
            "https://www.ssl.com/article/what-is-an-ssl-certificate/",
            "https://www.digicert.com/ssl/what-is-ssl"
        ]
    },
    sqlInjection: {
        title: "SQL Injection",
        description: "SQL injection is a code injection technique that exploits a vulnerability in an application's software by manipulating SQL queries.",
        examples: [
            "Using unsanitized user input in SQL queries.",
            "Exposing database error messages to users."
        ],
        resources: [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://www.acunetix.com/blog/articles/sql-injection/"
        ]
    },
    xss: {
        title: "Cross-Site Scripting (XSS)",
        description: "XSS is a vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users.",
        examples: [
            "Injecting scripts through user input fields.",
            "Exploiting reflected XSS through URL parameters."
        ],
        resources: [
            "https://owasp.org/www-community/attacks/xss/",
            "https://www.acunetix.com/blog/articles/cross-site-scripting-xss/"
        ]
    },
    csrf: {
        title: "Cross-Site Request Forgery (CSRF)",
        description: "CSRF is an attack that tricks the user into submitting a malicious request.",
        examples: [
            "Submitting forms without CSRF tokens.",
            "Exploiting authenticated sessions."
        ],
        resources: [
            "https://owasp.org/www-community/attacks/csrf",
            "https://www.acunetix.com/blog/articles/csrf/"
        ]
    },
    ssrf: {
        title: "Server-Side Request Forgery (SSRF)",
        description: "SSRF allows an attacker to send crafted requests from the server to internal or external resources.",
        examples: [
            "Accessing internal services through a vulnerable endpoint.",
            "Exploiting URL parameters to make requests."
        ],
        resources: [
            "https://owasp.org/www-community/attacks/Server-Side_Request_Forgery",
            "https://www.acunetix.com/blog/articles/server-side-request-forgery/"
        ]
    },
    idor: {
        title: "Insecure Direct Object References (IDOR)",
        description: "IDOR occurs when an application exposes a reference to an internal implementation object.",
        examples: [
            "Accessing user data by manipulating URL parameters.",
            "Exploiting predictable object IDs."
        ],
        resources: [
            "https://owasp.org/www-community/attacks/IDOR",
            "https://www.acunetix.com/blog/articles/idor/"
        ]
    },
    ldap: {
        title: "LDAP Injection",
        description: "LDAP injection is an attack that exploits vulnerabilities in applications that construct LDAP queries.",
        examples: [
            "Manipulating LDAP queries through user input.",
            "Exposing sensitive data through LDAP queries."
        ],
        resources: [
            "https://owasp.org/www-community/attacks/LDAP_Injection",
            "https://www.acunetix.com/blog/articles/ldap-injection/"
        ]
    }
};

export default function VulnerabilityScanner() {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [results, setResults] = useState<ScanResults | null>(null)
  const [error, setError] = useState('')
  const [scanHistory, setScanHistory] = useState<ScanHistory[]>([])
  const [showHistory, setShowHistory] = useState(false)

  useEffect(() => {
    const savedHistory = localStorage.getItem('scanHistory')
    if (savedHistory) {
      try {
        setScanHistory(JSON.parse(savedHistory))
      } catch (error) {
        console.error('Error loading scan history:', error)
        localStorage.removeItem('scanHistory')
      }
    }
  }, [])

  useEffect(() => {
    localStorage.setItem('scanHistory', JSON.stringify(scanHistory))
  }, [scanHistory])

  const handleScan = async () => {
    setScanning(true)
    setError('')
    setResults(null)

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Scan failed')
      }

      setResults(data)
      
      try {
        const newScan: ScanHistory = {
          url,
          timestamp: new Date().toISOString(),
          results: data
        }
        setScanHistory(prev => {
          const updatedHistory = [newScan, ...prev]
          const maxHistorySize = 50
          return updatedHistory.slice(0, maxHistorySize)
        })
      } catch (error) {
        console.error('Error saving to scan history:', error)
      }

    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to perform scan. Please try again.')
    } finally {
      setScanning(false)
    }
  }

  const particlesInit = useCallback(async (engine: Engine) => {
    await loadSlim(engine)
  }, [])

  const particlesLoaded = useCallback(async (container: Container | undefined) => {
    console.log(container)
  }, [])

  const chartData = results ? [
    { 
      name: 'SSL Certificate', 
      value: results.sslCertificate.status === 'secure' ? 100 : 0,
      color: results.sslCertificate.status === 'secure' ? '#10B981' : '#EF4444'
    },
    { 
      name: 'SQL Injection', 
      value: results.sqlInjection.vulnerabilityLevel 
        ? Math.max(0, 100 - results.sqlInjection.vulnerabilityLevel)
        : (results.sqlInjection.status === 'secure' ? 100 : 0),
      color: results.sqlInjection.status === 'secure' ? '#10B981' : '#EF4444'
    },
    { 
      name: 'XSS', 
      value: results.xss.technicalDetails?.vulnerabilityScore 
        ? Math.max(0, 100 - results.xss.technicalDetails.vulnerabilityScore)
        : (results.xss.status === 'secure' ? 100 : 0),
      color: results.xss.status === 'secure' ? '#10B981' : '#EF4444'
    },
    { 
      name: 'HTTP Headers', 
      value: results.httpHeaders.vulnerabilityLevel 
        ? Math.max(0, 100 - results.httpHeaders.vulnerabilityLevel)
        : (results.httpHeaders.status === 'secure' ? 100 : 0),
      color: results.httpHeaders.status === 'secure' ? '#10B981' : '#EF4444'
    },
    { 
      name: 'CSRF', 
      value: results.csrf.vulnerabilityLevel 
        ? Math.max(0, 100 - results.csrf.vulnerabilityLevel)
        : (results.csrf.status === 'secure' ? 100 : 0),
      color: results.csrf.status === 'secure' ? '#10B981' : '#EF4444'
    },
    { 
      name: 'SSRF', 
      value: results.ssrf.vulnerabilityLevel 
        ? Math.max(0, 100 - results.ssrf.vulnerabilityLevel)
        : (results.ssrf.status === 'secure' ? 100 : 0),
      color: results.ssrf.status === 'secure' ? '#10B981' : '#EF4444'
    },
    { 
      name: 'IDOR', 
      value: results.idor.vulnerabilityLevel 
        ? Math.max(0, 100 - results.idor.vulnerabilityLevel)
        : (results.idor.status === 'secure' ? 100 : 0),
      color: results.idor.status === 'secure' ? '#10B981' : '#EF4444'
    },
    { 
      name: 'LDAP', 
      value: results.ldap.vulnerabilityLevel 
        ? Math.max(0, 100 - results.ldap.vulnerabilityLevel)
        : (results.ldap.status === 'secure' ? 100 : 0),
      color: results.ldap.status === 'secure' ? '#10B981' : '#EF4444'
    },
  ].map(item => ({
    ...item,
    color: item.value >= 70 ? '#10B981' :
           item.value >= 40 ? '#FBBF24' :
           '#EF4444'
  })) : [];

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const value = payload[0].value;
      let riskLevel = value >= 70 ? 'Low Risk' :
                      value >= 40 ? 'Medium Risk' : 
                      'High Risk';
      
      return (
        <div className="bg-white p-4 rounded-lg shadow-lg border">
          <p className="font-semibold">{label}</p>
          <p className="text-sm">
            Security Score: 
            <span className={`ml-2 font-bold ${
              value >= 70 ? 'text-green-500' :
              value >= 40 ? 'text-yellow-500' :
              'text-red-500'
            }`}>
              {value.toFixed(1)}%
            </span>
          </p>
          <p className="text-xs mt-1 text-gray-500">
            {riskLevel}
          </p>
        </div>
      );
    }
    return null;
  };

  const generatePDF = async () => {
    if (!results) return;

    const pdf = new jsPDF();
    const pageWidth = pdf.internal.pageSize.width;

    // Add title
    pdf.setFontSize(20);
    pdf.text('Security Scan Report', pageWidth / 2, 15, { align: 'center' });

    // Add scan information
    pdf.setFontSize(12);
    pdf.text(`URL: ${url}`, 14, 25);
    pdf.text(`Scan Date: ${new Date().toLocaleString()}`, 14, 32);

    // Add overview section
    pdf.setFontSize(16);
    pdf.text('Security Overview', 14, 45);

    // Capture the chart
    const chartElement = document.querySelector('.chart-container');
    if (chartElement) {
      const canvas = await html2canvas(chartElement);
      const chartImage = canvas.toDataURL('image/png');
      pdf.addImage(chartImage, 'PNG', 14, 50, 180, 100);
    }

    // Add SSL Certificate details
    pdf.addPage();
    pdf.setFontSize(16);
    pdf.text('SSL Certificate Details', 14, 15);
    
    const sslData = [
      ['Issuer', results.sslCertificate.issuer || 'Unknown'],
      ['Subject', results.sslCertificate.subject || 'Unknown'],
      ['Valid From', results.sslCertificate.validFrom || 'Unknown'],
      ['Valid To', results.sslCertificate.validTo || 'Unknown'],
      ['Self-Signed', results.sslCertificate.selfSigned ? 'Yes' : 'No'],
      ['Status', results.sslCertificate.status],
      ['Details', results.sslCertificate.details],
    ];

    autoTable(pdf, {
      startY: 25,
      head: [['Property', 'Value']],
      body: sslData,
    });

    // Add SQL Injection details
    pdf.addPage();
    pdf.setFontSize(16);
    pdf.text('SQL Injection Analysis', 14, 15);

    const sqlData = [
      ['Status', results.sqlInjection.status],
      ['Details', results.sqlInjection.details],
      ['Vulnerability Score', results.sqlInjection.vulnerabilityLevel?.toString() || 'N/A'],
    ];

    if (results.sqlInjection.technicalDetails) {
      Object.entries(results.sqlInjection.technicalDetails).forEach(([key, value]) => {
        if (typeof value === 'boolean') {
          sqlData.push([key, value ? 'Yes' : 'No']);
        }
      });
    }

    autoTable(pdf, {
      startY: 25,
      head: [['Property', 'Value']],
      body: sqlData,
    });

    // Add XSS details
    pdf.addPage();
    pdf.setFontSize(16);
    pdf.text('XSS Vulnerability Analysis', 14, 15);

    const xssData = [
      ['Status', results.xss.status],
      ['Details', results.xss.details],
    ];

    if (results.xss.technicalDetails) {
      const tech = results.xss.technicalDetails;
      xssData.push(['Vulnerability Score', `${tech.vulnerabilityScore}/100`]);
      
      if (tech.dangerousScripts > 0) {
        xssData.push(['Dangerous Scripts', tech.dangerousScripts.toString()]);
      }
      if (tech.unsafeEventHandlers > 0) {
        xssData.push(['Unsafe Event Handlers', tech.unsafeEventHandlers.toString()]);
      }
      if (tech.reflectedParameters > 0) {
        xssData.push(['Reflected Parameters', tech.reflectedParameters.toString()]);
      }
      if (tech.unsafeLinks > 0) {
        xssData.push(['Unsafe Links', tech.unsafeLinks.toString()]);
      }
      if (tech.unsafeIframes > 0) {
        xssData.push(['Unsafe Iframes', tech.unsafeIframes.toString()]);
      }
      if (tech.vulnerableInputs > 0) {
        xssData.push(['Vulnerable Inputs', tech.vulnerableInputs.toString()]);
      }
      if (tech.unsanitizedData > 0) {
        xssData.push(['Unsanitized Data', tech.unsanitizedData.toString()]);
      }
    }

    autoTable(pdf, {
      startY: 25,
      head: [['Property', 'Value']],
      body: xssData,
    });

    // Add detailed findings if they exist
    if (results.xss.technicalDetails?.findings?.length > 0) {
      pdf.addPage();
      pdf.setFontSize(16);
      pdf.text('Detailed XSS Findings', 14, 15);

      const findingsData = results.xss.technicalDetails.findings.map((finding, index) => [
        `Issue ${index + 1}`,
        finding
      ]);

      autoTable(pdf, {
        startY: 25,
        head: [['Issue #', 'Description']],
        body: findingsData,
      });
    }

    // Add HTTP Headers details
    pdf.addPage();
    pdf.setFontSize(16);
    pdf.text('HTTP Headers Analysis', 14, 15);

    const headersData = [
      ['Status', results.httpHeaders.status],
      ['Details', results.httpHeaders.details],
      ['Security Score', `${100 - results.httpHeaders.technicalDetails.vulnerabilityScore}/100`],
      ['Total Headers Checked', results.httpHeaders.technicalDetails.totalHeadersChecked.toString()],
      ['Present Headers', results.httpHeaders.technicalDetails.presentHeadersCount.toString()],
      ['Missing Headers', results.httpHeaders.technicalDetails.missingHeadersCount.toString()],
      ['Weak Headers', results.httpHeaders.technicalDetails.weakHeadersCount.toString()],
    ];

    autoTable(pdf, {
      startY: 25,
      head: [['Property', 'Value']],
      body: headersData,
    });

    // Add Missing Headers Details
    if (results.httpHeaders.technicalDetails.missingHeaders.length > 0) {
      pdf.addPage();
      pdf.setFontSize(16);
      pdf.text('Missing Security Headers', 14, 15);

      const missingHeadersData = results.httpHeaders.technicalDetails.headerDetails
        .filter(header => header.status === 'Missing')
        .map(header => [
          header.header,
          header.description
        ]);

      autoTable(pdf, {
        startY: 25,
        head: [['Missing Header', 'Description']],
        body: missingHeadersData,
      });
    }

    // Add Present Headers Details
    if (results.httpHeaders.technicalDetails.presentHeaders.length > 0) {
      pdf.addPage();
      pdf.setFontSize(16);
      pdf.text('Present Security Headers', 14, 15);

      const presentHeadersData = results.httpHeaders.technicalDetails.headerDetails
        .filter(header => header.status === 'Present')
        .map(header => [
          header.header,
          header.value || 'No value',
          header.description
        ]);

      autoTable(pdf, {
        startY: 25,
        head: [['Header', 'Value', 'Description']],
        body: presentHeadersData,
      });
    }

    // Add Weak Headers Details
    if (results.httpHeaders.technicalDetails.weakHeaders.length > 0) {
      pdf.addPage();
      pdf.setFontSize(16);
      pdf.text('Weak Header Configurations', 14, 15);

      const weakHeadersData = results.httpHeaders.technicalDetails.weakHeaders.map(header => [header]);

      autoTable(pdf, {
        startY: 25,
        head: [['Weak Configuration']],
        body: weakHeadersData,
      });
    }

    // Add CSRF details
    pdf.addPage();
    pdf.setFontSize(16);
    pdf.text('CSRF Vulnerability Analysis', 14, 15);

    const csrfData = [
      ['Status', results.csrf.status],
      ['Details', results.csrf.details],
    ];

    if (results.csrf.technicalDetails) {
      const tech = results.csrf.technicalDetails;
      csrfData.push(['Vulnerability Score', `${tech.vulnerabilityScore}/100`]);
      csrfData.push(['Total Issues', tech.totalIssues.toString()]);
    }

    autoTable(pdf, {
      startY: 25,
      head: [['Property', 'Value']],
      body: csrfData,
    });

    // Add detailed findings if they exist
    if (results.csrf.technicalDetails?.findings.length > 0) {
      pdf.addPage();
      pdf.setFontSize(16);
      pdf.text('Detailed CSRF Findings', 14, 15);

      const findingsData = results.csrf.technicalDetails.findings.map((finding, index) => [
        `Issue ${index + 1}`,
        finding
      ]);

      autoTable(pdf, {
        startY: 25,
        head: [['Issue #', 'Description']],
        body: findingsData,
      });
    }

    // Add SSRF details
    pdf.addPage();
    pdf.setFontSize(16);
    pdf.text('SSRF Vulnerability Analysis', 14, 15);

    const ssrfData = [
      ['Status', results.ssrf.status],
      ['Details', results.ssrf.details],
    ];

    if (results.ssrf.technicalDetails) {
      const tech = results.ssrf.technicalDetails;
      ssrfData.push(['Vulnerability Score', `${tech.vulnerabilityScore}/100`]);
      ssrfData.push(['Total Issues', tech.totalIssues.toString()]);
    }

    autoTable(pdf, {
      startY: 25,
      head: [['Property', 'Value']],
      body: ssrfData,
    });

    // Add detailed findings if they exist
    if (results.ssrf.technicalDetails?.findings.length > 0) {
      pdf.addPage();
      pdf.setFontSize(16);
      pdf.text('Detailed SSRF Findings', 14, 15);

      const findingsData = results.ssrf.technicalDetails.findings.map((finding, index) => [
        `Issue ${index + 1}`,
        finding
      ]);

      autoTable(pdf, {
        startY: 25,
        head: [['Issue #', 'Description']],
        body: findingsData,
      });
    }

    // Add IDOR details
    pdf.addPage();
    pdf.setFontSize(16);
    pdf.text('IDOR Vulnerability Analysis', 14, 15);

    const idorData = [
      ['Status', results.idor.status],
      ['Details', results.idor.details],
    ];

    if (results.idor.technicalDetails) {
      const tech = results.idor.technicalDetails;
      idorData.push(['Vulnerability Score', `${tech.vulnerabilityScore}/100`]);
      idorData.push(['Total Issues', tech.totalIssues.toString()]);
    }

    autoTable(pdf, {
      startY: 25,
      head: [['Property', 'Value']],
      body: idorData,
    });

    // Add detailed findings if they exist
    if (results.idor.technicalDetails?.findings.length > 0) {
      pdf.addPage();
      pdf.setFontSize(16);
      pdf.text('Detailed IDOR Findings', 14, 15);

      const findingsData = results.idor.technicalDetails.findings.map((finding, index) => [
        `Issue ${index + 1}`,
        finding
      ]);

      autoTable(pdf, {
        startY: 25,
        head: [['Issue #', 'Description']],
        body: findingsData,
      });
    }

    // Add LDAP details
    pdf.addPage();
    pdf.setFontSize(16);
    pdf.text('LDAP Injection Analysis', 14, 15);

    const ldapData = [
      ['Status', results.ldap.status],
      ['Details', results.ldap.details],
    ];

    if (results.ldap.technicalDetails) {
      const tech = results.ldap.technicalDetails;
      ldapData.push(['Vulnerability Score', `${tech.vulnerabilityScore}/100`]);
      ldapData.push(['Total Issues', tech.totalIssues.toString()]);
    }

    autoTable(pdf, {
      startY: 25,
      head: [['Property', 'Value']],
      body: ldapData,
    });

    // Add detailed findings if they exist
    if (results.ldap.technicalDetails?.findings.length > 0) {
      pdf.addPage();
      pdf.setFontSize(16);
      pdf.text('Detailed LDAP Findings', 14, 15);

      const findingsData = results.ldap.technicalDetails.findings.map((finding, index) => [
        `Issue ${index + 1}`,
        finding
      ]);

      autoTable(pdf, {
        startY: 25,
        head: [['Issue #', 'Description']],
        body: findingsData,
      });
    }

    // Save the PDF
    pdf.save(`security-scan-report-${new Date().toISOString().split('T')[0]}.pdf`);
  };

  const DownloadButton = () => (
    <div className="mt-6 border-t pt-6">
      <div className="rounded-lg bg-gray-50 p-4">
        <div className="flex flex-col space-y-3">
          <div className="flex items-center space-x-3">
            <div className="rounded-full bg-blue-100 p-2">
              <Download className="h-5 w-5 text-blue-600" />
            </div>
            <div>
              <h4 className="font-semibold">Download Detailed Report</h4>
              <p className="text-sm text-gray-500">Get a comprehensive PDF report of all security findings</p>
            </div>
          </div>
          <Button 
            onClick={generatePDF}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white"
            size="lg"
          >
            <Download className="mr-2 h-4 w-4" />
            Download Security Report
          </Button>
        </div>
        <div className="mt-3 flex items-center justify-between text-xs text-gray-500">
          <span className="flex items-center">
            <AlertTriangle className="mr-1 h-4 w-4" />
            PDF format
          </span>
          <span>
            {new Date().toLocaleDateString()}
          </span>
        </div>
      </div>
    </div>
  );

  const clearHistory = () => {
    setScanHistory([])
    localStorage.removeItem('scanHistory')
  }

  const deleteScan = (timestamp: string) => {
    setScanHistory(prev => {
      const newHistory = prev.filter(scan => scan.timestamp !== timestamp)
      localStorage.setItem('scanHistory', JSON.stringify(newHistory))
      return newHistory
    })
  }

  const ScanHistoryPanel = ({ 
    history, 
    onSelect, 
    onClose,
    onClear,
    onDelete 
  }: { 
    history: ScanHistory[]; 
    onSelect: (results: ScanResults) => void;
    onClose: () => void;
    onClear: () => void;
    onDelete: (timestamp: string) => void;
  }) => (
    <Card className="absolute right-0 top-0 h-full w-96 bg-white/95 shadow-xl z-50 transition-all duration-300 ease-in-out">
      <CardHeader className="border-b bg-gray-50/50 sticky top-0 z-10">
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center">
              <Clock className="h-5 w-5 mr-2 text-blue-600" />
              Scan History
            </CardTitle>
            <CardDescription>
              {history.length} previous {history.length === 1 ? 'scan' : 'scans'}
            </CardDescription>
          </div>
          <div className="flex gap-2">
            {history.length > 0 && (
              <Button 
                variant="outline" 
                size="icon" 
                onClick={onClear}
                className="text-red-500 hover:text-red-700 hover:bg-red-50 transition-colors"
                title="Clear History"
              >
                <Trash2 className="h-4 w-4" />
              </Button>
            )}
            <Button 
              variant="ghost" 
              size="icon" 
              onClick={onClose}
              className="hover:bg-gray-100 transition-colors"
            >
              <XCircle className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="overflow-auto max-h-[calc(100vh-120px)] p-4">
        {history.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 text-gray-500">
            <History className="h-12 w-12 mb-4 text-gray-400" />
            <p className="text-sm text-center">No scan history available</p>
            <p className="text-xs text-center mt-1">Completed scans will appear here</p>
          </div>
        ) : (
          <div className="space-y-4">
            {history.map((scan, index) => (
              <Card 
                key={index} 
                className="group cursor-pointer hover:shadow-md transition-all duration-200 border-gray-200 hover:border-blue-200"
              >
                <CardHeader className="p-4 space-y-3">
                  <div className="flex justify-between items-start">
                    <div className="flex-1 min-w-0">
                      <CardTitle className="text-sm truncate max-w-[250px] group-hover:text-blue-600 transition-colors">
                        {scan.url}
                      </CardTitle>
                      <CardDescription className="text-xs flex items-center mt-1">
                        <Calendar className="h-3 w-3 mr-1 flex-shrink-0" />
                        {new Date(scan.timestamp).toLocaleString()}
                      </CardDescription>
                    </div>
                    <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity ml-2 flex-shrink-0">
                      <Button 
                        variant="ghost" 
                        size="icon"
                        className="hover:bg-red-50 hover:text-red-600"
                        onClick={(e) => {
                          e.stopPropagation();
                          onDelete(scan.timestamp);
                        }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                      <Button 
                        variant="ghost" 
                        size="icon"
                        className="hover:bg-blue-50 hover:text-blue-600"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelect(scan.results);
                        }}
                      >
                        <ArrowRight className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(scan.results).map(([key, value]) => {
                      const score = key === 'sslCertificate' 
                        ? (value.status === 'secure' ? 100 : 0)
                        : (value.vulnerabilityLevel 
                          ? Math.max(0, 100 - value.vulnerabilityLevel) 
                          : (value.status === 'secure' ? 100 : 0));

                      return (
                        <div 
                          key={key}
                          className={`
                            text-xs px-2 py-1.5 rounded-md flex items-center justify-between
                            ${score >= 70 ? 'bg-green-50 text-green-700 border border-green-200' :
                              score >= 40 ? 'bg-yellow-50 text-yellow-700 border border-yellow-200' :
                              'bg-red-50 text-red-700 border border-red-200'}
                          `}
                        >
                          <span>{key.replace(/([A-Z])/g, ' $1').trim()}</span>
                          <span className="font-medium">{score}%</span>
                        </div>
                      );
                    })}
                  </div>
                </CardHeader>
              </Card>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );

  return (
    <div className="relative min-h-screen bg-[#0d47a1]">
      {scanning && <ScanningAnimation />}
      {showHistory && (
        <ScanHistoryPanel
          history={scanHistory}
          onSelect={(selectedResults) => {
            setResults(selectedResults)
            setShowHistory(false)
          }}
          onClose={() => setShowHistory(false)}
          onClear={clearHistory}
          onDelete={deleteScan}
        />
      )}
      
      <Particles
        id="tsparticles"
        init={particlesInit}
        loaded={particlesLoaded}
        className="absolute inset-0"
        options={{
          background: {
            color: {
              value: "transparent",
            },
          },
          fpsLimit: 120,
          interactivity: {
            events: {
              onClick: {
                enable: true,
                mode: "push",
              },
              onHover: {
                enable: true,
                mode: "repulse",
              },
              resize: true,
            },
            modes: {
              push: {
                quantity: 4,
              },
              repulse: {
                distance: 200,
                duration: 0.4,
              },
            },
          },
          particles: {
            color: {
              value: "#ffffff",
            },
            links: {
              color: "#ffffff",
              distance: 150,
              enable: true,
              opacity: 0.5,
              width: 1,
            },
            move: {
              direction: "none",
              enable: true,
              outModes: {
                default: "bounce",
              },
              random: false,
              speed: 6,
              straight: false,
            },
            number: {
              density: {
                enable: true,
                area: 800,
              },
              value: 80,
            },
            opacity: {
              value: 0.5,
            },
            shape: {
              type: "circle",
            },
            size: {
              value: { min: 1, max: 5 },
            },
          },
          detectRetina: true,
        }}
      />
      <div className="relative z-10 min-h-screen flex flex-col p-6">
        <div className="mb-6">
          <h1 className="text-3xl font-bold text-white">Security Dashboard</h1>
          <p className="text-gray-200">Analyze and monitor website vulnerabilities</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-grow">
          <Card className="lg:col-span-1 bg-white/95 backdrop-blur-sm h-fit">
            <CardHeader>
              <CardTitle>Scan Control</CardTitle>
              <CardDescription>Enter website URL to begin scanning</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowHistory(!showHistory)}
                    className="mb-2"
                  >
                    {showHistory ? 'Hide History' : 'Show History'}
                  </Button>
                  <span className="text-sm text-gray-500">
                    {scanHistory.length} scans
                  </span>
                </div>
                <Input
                  type="url"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="w-full"
                />
                <Button 
                  onClick={handleScan} 
                  disabled={scanning || !url}
                  className="w-full"
                >
                  {scanning ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    'Start Scan'
                  )}
                </Button>

                {error && (
                  <Alert variant="destructive">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle>Error</AlertTitle>
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}
              </div>
            </CardContent>
          </Card>

          <Card className="lg:col-span-2 bg-white/95 backdrop-blur-sm h-fit">
            <CardHeader>
              <CardTitle>Scan Results</CardTitle>
              <CardDescription>
                {results ? 'Detailed vulnerability analysis' : 'No scan results available'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {results ? (
                <>
                  <Tabs defaultValue="overview" className="w-full">
                    <TabsList className="grid w-full grid-cols-4 mb-4">
                      <TabsTrigger value="overview">Overview</TabsTrigger>
                      <TabsTrigger value="ssl">SSL Certificate</TabsTrigger>
                      <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                      <TabsTrigger value="headers">HTTP Headers</TabsTrigger>
                    </TabsList>

                    <TabsContent value="overview">
                      <div className="space-y-4">
                        <h3 className="text-lg font-semibold">Security Score Overview</h3>
                        
                        <div className="bg-white shadow-md rounded-lg p-6">
                          <h4 className="text-xl font-bold mb-2">Overall Score</h4>
                          <p className="text-2xl font-semibold text-center text-gray-800">{results.overallScore.toFixed(2)}%</p>
                          <Progress value={results.overallScore} className="mt-4" />
                          
                          <div className="text-center mt-2">
                            {results.overallScore >= 70 && (
                              <span className="text-green-600 font-semibold">Status: Secure</span>
                            )}
                            {results.overallScore >= 40 && results.overallScore < 70 && (
                              <span className="text-yellow-600 font-semibold">Status: Moderate Risk</span>
                            )}
                            {results.overallScore < 40 && (
                              <span className="text-red-600 font-semibold">Status: High Risk</span>
                            )}
                          </div>

                          <p className="text-center mt-2 text-sm text-gray-500">
                            {results.overallScore >= 70 ? 'Good security practices in place' :
                             results.overallScore >= 40 ? 'Some vulnerabilities detected' :
                             'Critical vulnerabilities present'}
                          </p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <Card className={`border ${results.overallScore >= 70 ? 'border-green-200 bg-green-50' : ''}`}>
                            <CardHeader>
                              <CardTitle className="text-sm text-green-700">Low Risk (70-100%)</CardTitle>
                              <CardDescription className="text-green-600">
                                Good security practices in place
                              </CardDescription>
                            </CardHeader>
                          </Card>
                          <Card className={`border ${results.overallScore >= 40 && results.overallScore < 70 ? 'border-yellow-200 bg-yellow-50' : ''}`}>
                            <CardHeader>
                              <CardTitle className="text-sm text-yellow-700">Medium Risk (40-69%)</CardTitle>
                              <CardDescription className="text-yellow-600">
                                Some vulnerabilities detected
                              </CardDescription>
                            </CardHeader>
                          </Card>
                          <Card className={`border ${results.overallScore < 40 ? 'border-red-200 bg-red-50' : ''}`}>
                            <CardHeader>
                              <CardTitle className="text-sm text-red-700">High Risk (0-39%)</CardTitle>
                              <CardDescription className="text-red-600">
                                Critical vulnerabilities present
                              </CardDescription>
                            </CardHeader>
                          </Card>
                        </div>

                        <div className="h-[400px] bg-white/50 rounded-xl p-4 chart-container">
                          <ResponsiveContainer width="100%" height="100%">
                            <BarChart
                              data={chartData}
                              margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
                            >
                              <defs>
                                {chartData.map((entry, index) => (
                                  <linearGradient
                                    key={`gradient-${index}`}
                                    id={`gradient-${index}`}
                                    x1="0"
                                    y1="0"
                                    x2="0"
                                    y2="1"
                                  >
                                    <stop
                                      offset="5%"
                                      stopColor={entry.color}
                                      stopOpacity={0.8}
                                    />
                                    <stop
                                      offset="95%"
                                      stopColor={entry.color}
                                      stopOpacity={0.3}
                                    />
                                  </linearGradient>
                                ))}
                              </defs>
                              <CartesianGrid 
                                strokeDasharray="3 3" 
                                vertical={false} 
                                stroke="#E5E7EB"
                              />
                              <XAxis 
                                dataKey="name" 
                                axisLine={false}
                                tickLine={false}
                                tick={{ fill: '#6B7280', fontSize: 12 }}
                              />
                              <YAxis 
                                axisLine={false}
                                tickLine={false}
                                tick={{ fill: '#6B7280', fontSize: 12 }}
                                domain={[0, 100]}
                              />
                              <Tooltip content={<CustomTooltip />} />
                              <Bar 
                                dataKey="value" 
                                radius={[8, 8, 0, 0]}
                                maxBarSize={60}
                              >
                                {chartData.map((entry, index) => (
                                  <Cell
                                    key={`cell-${index}`}
                                    fill={`url(#gradient-${index})`}
                                    className="transition-all duration-300 hover:opacity-80"
                                  />
                                ))}
                              </Bar>
                              <Area
                                type="monotone"
                                dataKey="value"
                                stroke="#8884d8"
                                fillOpacity={0.1}
                                fill="#8884d8"
                              />
                            </BarChart>
                          </ResponsiveContainer>
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                          {Object.entries(results).map(([key, value]) => {
                            const score = key === 'sslCertificate' 
                              ? (value.status === 'secure' ? 100 : 0)
                              : (value.vulnerabilityLevel 
                                ? Math.max(0, 100 - value.vulnerabilityLevel) 
                                : (value.status === 'secure' ? 100 : 0));

                            let riskLevel = '';
                            let bgColor = '';
                            let textColor = '';
                            let statusColor = '';

                            if (score >= 70) {
                              riskLevel = 'Low Risk';
                              bgColor = 'bg-green-50';
                              textColor = 'text-green-700';
                              statusColor = 'text-green-500';
                            } else if (score >= 40) {
                              riskLevel = 'Medium Risk';
                              bgColor = 'bg-yellow-50';
                              textColor = 'text-yellow-700';
                              statusColor = 'text-yellow-500';
                            } else {
                              riskLevel = 'High Risk';
                              bgColor = 'bg-red-50';
                              textColor = 'text-red-700';
                              statusColor = 'text-red-500';
                            }

                            return (
                              <Card key={key} className={`${bgColor}`}>
                                <CardHeader className="p-4">
                                  <CardTitle className={`text-sm capitalize ${textColor}`}>
                                    {key.replace(/([A-Z])/g, ' $1').trim()}
                                  </CardTitle>
                                  <CardDescription className="flex flex-col mt-2">
                                    <span className={`flex items-center ${statusColor}`}>
                                      {score >= 70 ? (
                                        <CheckCircle className="h-5 w-5" />
                                      ) : score >= 40 ? (
                                        <AlertTriangle className="h-5 w-5" />
                                      ) : (
                                        <XCircle className="h-5 w-5" />
                                      )}
                                      <span className="ml-2 capitalize">{riskLevel}</span>
                                    </span>
                                    <span className={`text-sm mt-1 ${textColor}`}>
                                      Score: {score.toFixed(0)}%
                                    </span>
                                  </CardDescription>
                                </CardHeader>
                              </Card>
                            );
                          })}
                        </div>
                        <DownloadButton />
                      </div>
                    </TabsContent>

                    <TabsContent value="ssl" className="space-y-4">
                      <SSLResultItem title="SSL Certificate" result={results.sslCertificate} />
                    </TabsContent>

                    <TabsContent value="vulnerabilities" className="space-y-4">
                      <ResultItem title="SQL Injection" result={results.sqlInjection} />
                      <ResultItem title="XSS Vulnerability" result={results.xss} />
                      <ResultItem title="CSRF Vulnerability" result={results.csrf} />
                      <ResultItem title="SSRF Vulnerability" result={results.ssrf} />
                      <ResultItem title="IDOR Vulnerability" result={results.idor} />
                      <ResultItem title="LDAP Injection" result={results.ldap} />
                    </TabsContent>

                    <TabsContent value="headers" className="space-y-4">
                      <ResultItem title="HTTP Headers" result={results.httpHeaders} />
                    </TabsContent>
                  </Tabs>
                </>
              ) : (
                <div className="text-center py-12 text-gray-500">
                  <p>Enter a URL and click "Start Scan" to begin analysis</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

function SSLResultItem({ title, result }: { title: string; result: ScanResults['sslCertificate'] }) {
  const { 
    status, 
    details, 
    issuer, 
    subject, 
    validFrom, 
    validTo, 
    serialNumber, 
    selfSigned, 
    signatureAlgorithm, 
    publicKeyInfo,
    authorized,
    validChain,
    issuerChain
  } = result

  return (
    <Alert variant={status === 'vulnerable' ? 'destructive' : 'default'}>
      {status === 'vulnerable' ? (
        <XCircle className="h-4 w-4" />
      ) : (
        <CheckCircle className="h-4 w-4" />
      )}
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        <p>{details}</p>
        <table className="mt-2 w-full">
          <tbody>
            {issuer && <tr><td className="font-semibold">Issuer:</td><td>{issuer}</td></tr>}
            {subject && <tr><td className="font-semibold">Subject:</td><td>{subject}</td></tr>}
            {validFrom && <tr><td className="font-semibold">Valid From:</td><td>{validFrom}</td></tr>}
            {validTo && <tr><td className="font-semibold">Valid To:</td><td>{validTo}</td></tr>}
            {serialNumber && <tr><td className="font-semibold">Serial Number:</td><td>{serialNumber}</td></tr>}
            {selfSigned !== undefined && (
              <tr><td className="font-semibold">Self-Signed:</td><td>{selfSigned ? 'Yes' : 'No'}</td></tr>
            )}
            {signatureAlgorithm && <tr><td className="font-semibold">Signature Algorithm:</td><td>{signatureAlgorithm}</td></tr>}
            {publicKeyInfo && <tr><td className="font-semibold">Public Key Info:</td><td>{publicKeyInfo}</td></tr>}
            {authorized !== undefined && (
              <tr><td className="font-semibold">Authorized:</td><td>{authorized ? 'Yes' : 'No'}</td></tr>
            )}
            {validChain !== undefined && (
              <tr><td className="font-semibold">Valid Chain:</td><td>{validChain ? 'Yes' : 'No'}</td></tr>
            )}
            {issuerChain && <tr><td className="font-semibold">Issuer Chain:</td><td>{issuerChain}</td></tr>}
          </tbody>
        </table>
      </AlertDescription>
    </Alert>
  )
}

function ResultItem({ title, result }: { title: string; result: any }) {
  const { status, details, technicalDetails } = result
  return (
    <Alert variant={status === 'vulnerable' ? 'destructive' : 'default'}>
      {status === 'vulnerable' ? (
        <XCircle className="h-4 w-4" />
      ) : (
        <CheckCircle className="h-4 w-4" />
      )}
      <AlertTitle>{title}</AlertTitle>
      <AlertDescription>
        <p>{details}</p>
        {technicalDetails && (
          <div className="mt-2 text-sm">
            <p className="font-semibold">Summary:</p>
            {title === "HTTP Headers" ? (
              // HTTP Headers summary
              <div className="mt-2">
                <p>Security Score: {100 - technicalDetails.vulnerabilityScore}/100</p>
                <p className="mt-1">
                  Present Headers: {technicalDetails.presentHeadersCount} of {technicalDetails.totalHeadersChecked}
                </p>
                {status === 'vulnerable' && (
                  <p className="text-xs text-gray-500 mt-2">
                    Download the PDF report for detailed missing headers information
                  </p>
                )}
              </div>
            ) : title === "XSS Vulnerability" ? (
              // XSS summary
              <div className="mt-2">
                <p>Vulnerability Score: {technicalDetails.vulnerabilityScore}/100</p>
                <p className="mt-1">
                  {technicalDetails.findings?.length 
                    ? `Found ${technicalDetails.findings.length} potential issues`
                    : 'No issues found'}
                </p>
                {status === 'vulnerable' && (
                  <p className="text-xs text-gray-500 mt-2">
                    Download the PDF report for detailed findings
                  </p>
                )}
              </div>
            ) : (
              // SQL Injection and other summaries
              <div className="mt-2">
                <p>Vulnerability Score: {technicalDetails.vulnerabilityScore}/100</p>
                {status === 'vulnerable' && (
                  <>
                    <p className="mt-1">
                      {Object.entries(technicalDetails)
                        .filter(([key, value]) => value === true)
                        .length} potential vulnerabilities detected
                    </p>
                    <p className="text-xs text-gray-500 mt-2">
                      Download the PDF report for detailed findings
                    </p>
                  </>
                )}
              </div>
            )}
          </div>
        )}
      </AlertDescription>
    </Alert>
  )
}