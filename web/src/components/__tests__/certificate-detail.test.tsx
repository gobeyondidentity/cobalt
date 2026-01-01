import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { CertificateDetail } from '../certificate-detail'
import type { Certificate } from '@/lib/api'

// Sample certificate matching BlueField-3 structure
const mockCertificate: Certificate = {
  level: 1,
  subject: "CN=NVIDIA BF3 Identity,O=NVIDIA Corporation,OU=BlueField,C=US",
  issuer: "CN=NVIDIA BlueField IRoT Root CA,O=NVIDIA Corporation,C=US",
  notBefore: "2024-01-01T00:00:00Z",
  notAfter: "2034-01-01T00:00:00Z",
  algorithm: "ECDSA P-384",
  pem: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
  fingerprint: "abc123def456789012345678901234567890abcdef",
}

// Certificate that expires soon (within 30 days)
const expiringSoonCert: Certificate = {
  ...mockCertificate,
  notAfter: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000).toISOString(), // 15 days from now
}

// Expired certificate
const expiredCert: Certificate = {
  ...mockCertificate,
  notAfter: "2020-01-01T00:00:00Z",
}

describe('CertificateDetail', () => {
  it('parses and displays subject DN components', () => {
    render(<CertificateDetail certificate={mockCertificate} />)

    // Should extract and display CN (appears in title and subject section)
    const cnElements = screen.getAllByText('NVIDIA BF3 Identity')
    expect(cnElements.length).toBeGreaterThanOrEqual(1)
    // Should show organization (appears in Subject and Issuer)
    const orgElements = screen.getAllByText(/NVIDIA Corporation/)
    expect(orgElements.length).toBeGreaterThanOrEqual(1)
    // Should have Subject section
    expect(screen.getByText('Subject')).toBeInTheDocument()
  })

  it('parses and displays issuer DN components', () => {
    render(<CertificateDetail certificate={mockCertificate} />)

    // Should show issuer section
    expect(screen.getByText('Issuer')).toBeInTheDocument()
    expect(screen.getByText(/NVIDIA BlueField IRoT Root CA/)).toBeInTheDocument()
  })

  it('shows validity period with dates', () => {
    render(<CertificateDetail certificate={mockCertificate} />)

    // Should show validity section
    expect(screen.getByText('Validity')).toBeInTheDocument()
    // Should show the date range with "to" separator
    expect(screen.getByText('to')).toBeInTheDocument()
    // Dates are formatted based on locale, just verify years are present somewhere
    expect(screen.getByText(/2024|2023/)).toBeInTheDocument() // Start date (may show Dec 31 2023 in some TZ)
    expect(screen.getByText(/2034|2033/)).toBeInTheDocument() // End date (may show Dec 31 2033 in some TZ)
  })

  it('displays algorithm information', () => {
    render(<CertificateDetail certificate={mockCertificate} />)

    expect(screen.getByText('Algorithm')).toBeInTheDocument()
    expect(screen.getByText('ECDSA P-384')).toBeInTheDocument()
  })

  it('shows certificate level', () => {
    render(<CertificateDetail certificate={mockCertificate} />)

    expect(screen.getByText('Level')).toBeInTheDocument()
    expect(screen.getByText('L1')).toBeInTheDocument()
  })

  it('shows fingerprint when available', () => {
    render(<CertificateDetail certificate={mockCertificate} />)

    expect(screen.getByText('Fingerprint')).toBeInTheDocument()
    // Should show truncated fingerprint
    expect(screen.getByText(/abc123def456/)).toBeInTheDocument()
  })

  it('shows valid status for non-expired certificate', () => {
    render(<CertificateDetail certificate={mockCertificate} />)

    expect(screen.getByText('Valid')).toBeInTheDocument()
  })

  it('shows expiring soon warning', () => {
    render(<CertificateDetail certificate={expiringSoonCert} />)

    expect(screen.getByText(/Expires Soon/)).toBeInTheDocument()
  })

  it('shows expired status for expired certificate', () => {
    render(<CertificateDetail certificate={expiredCert} />)

    expect(screen.getByText('Expired')).toBeInTheDocument()
  })

  it('handles certificate without fingerprint', () => {
    const certWithoutFingerprint: Certificate = {
      ...mockCertificate,
      fingerprint: undefined,
    }

    render(<CertificateDetail certificate={certWithoutFingerprint} />)

    // Should still render without fingerprint section
    const cnElements = screen.getAllByText('NVIDIA BF3 Identity')
    expect(cnElements.length).toBeGreaterThanOrEqual(1)
    expect(screen.queryByText('Fingerprint')).not.toBeInTheDocument()
  })

  it('handles minimal DN (CN only)', () => {
    const minimalCert: Certificate = {
      ...mockCertificate,
      subject: "CN=Simple Name",
      issuer: "CN=Simple Issuer",
    }

    render(<CertificateDetail certificate={minimalCert} />)

    // CN appears in title and subject section
    const cnElements = screen.getAllByText('Simple Name')
    expect(cnElements.length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/Simple Issuer/)).toBeInTheDocument()
  })
})
