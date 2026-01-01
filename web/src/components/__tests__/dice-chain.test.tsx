import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { DiceChain } from '../dice-chain'
import type { ChainsResponse } from '@/lib/api'

// Sample test data matching real BlueField-3 certificate structure
const mockChainsData: ChainsResponse = {
  irot: {
    certificates: [
      {
        level: 0,
        subject: "CN=NVIDIA BlueField IRoT Root CA",
        issuer: "CN=NVIDIA Device Identity CA",
        notBefore: "2024-01-01T00:00:00Z",
        notAfter: "2034-01-01T00:00:00Z",
        algorithm: "ECDSA P-384",
        pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        fingerprint: "abc123def456",
      },
      {
        level: 1,
        subject: "CN=NVIDIA BF3 Identity",
        issuer: "CN=NVIDIA BlueField IRoT Root CA",
        notBefore: "2024-01-01T00:00:00Z",
        notAfter: "2034-01-01T00:00:00Z",
        algorithm: "ECDSA P-384",
        pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        fingerprint: "ghi789jkl012",
      },
    ],
    error: null,
  },
  erot: {
    certificates: [
      {
        level: 0,
        subject: "CN=NVIDIA BlueField ERoT Root CA",
        issuer: "CN=NVIDIA Device Identity CA",
        notBefore: "2024-01-01T00:00:00Z",
        notAfter: "2034-01-01T00:00:00Z",
        algorithm: "ECDSA P-384",
        pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        fingerprint: "abc123def456", // Same as IRoT root = shared
      },
      {
        level: 1,
        subject: "CN=Microchip CEC173x",
        issuer: "CN=NVIDIA BlueField ERoT Root CA",
        notBefore: "2024-01-01T00:00:00Z",
        notAfter: "2034-01-01T00:00:00Z",
        algorithm: "ECDSA P-384",
        pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        fingerprint: "mno345pqr678",
      },
    ],
    error: null,
  },
  sharedRoot: {
    level: 0,
    subject: "CN=NVIDIA BlueField IRoT Root CA",
    issuer: "CN=NVIDIA Device Identity CA",
    notBefore: "2024-01-01T00:00:00Z",
    notAfter: "2034-01-01T00:00:00Z",
    algorithm: "ECDSA P-384",
    pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
    fingerprint: "abc123def456",
  },
}

describe('DiceChain', () => {
  it('renders IRoT chain hierarchy', () => {
    render(<DiceChain chains={mockChainsData} />)

    // Check for IRoT Chain title
    expect(screen.getByText('IRoT Chain')).toBeInTheDocument()
    // Check for certificate in the chain (there may be multiple IRoT references)
    expect(screen.getByText('NVIDIA BF3 Identity')).toBeInTheDocument()
  })

  it('renders ERoT chain hierarchy', () => {
    render(<DiceChain chains={mockChainsData} />)

    // Check for ERoT Chain title
    expect(screen.getByText('ERoT Chain')).toBeInTheDocument()
    expect(screen.getByText('Microchip CEC173x')).toBeInTheDocument()
  })

  it('highlights shared root when present', () => {
    render(<DiceChain chains={mockChainsData} />)

    // The shared root banner should be visible
    expect(screen.getByText(/Both chains share the same NVIDIA Device Identity CA root/i)).toBeInTheDocument()
  })

  it('expands certificate on click', async () => {
    render(<DiceChain chains={mockChainsData} />)

    // Click on a certificate to expand
    const certNode = screen.getByText(/NVIDIA BF3 Identity/i)
    fireEvent.click(certNode)

    // Should show expanded details
    expect(screen.getByText(/Algorithm/i)).toBeInTheDocument()
    expect(screen.getByText(/ECDSA P-384/i)).toBeInTheDocument()
  })

  it('shows validity status colors for valid certificates', () => {
    render(<DiceChain chains={mockChainsData} />)

    // Valid certificates should have success styling (not expired)
    // We check for the presence of valid status indicator
    const validIndicators = screen.getAllByTestId('cert-status-valid')
    expect(validIndicators.length).toBeGreaterThan(0)
  })

  it('handles empty chains gracefully', () => {
    const emptyChains: ChainsResponse = {
      irot: { certificates: [], error: null },
      erot: { certificates: [], error: null },
    }

    render(<DiceChain chains={emptyChains} />)

    expect(screen.getByText(/No certificates/i)).toBeInTheDocument()
  })

  it('displays error state when chain has error', () => {
    const errorChains: ChainsResponse = {
      irot: { certificates: [], error: "Failed to fetch IRoT chain" },
      erot: { certificates: [], error: null },
    }

    render(<DiceChain chains={errorChains} />)

    expect(screen.getByText(/Failed to fetch IRoT chain/i)).toBeInTheDocument()
  })
})
