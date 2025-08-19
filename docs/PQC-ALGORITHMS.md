# Post-Quantum Cryptography in PQC-VPN

This document explains the Post-Quantum Cryptography (PQC) algorithms used in PQC-VPN and their significance in protecting against quantum computing threats.

## Table of Contents

- [Introduction to Post-Quantum Cryptography](#introduction-to-post-quantum-cryptography)
- [NIST Standardization](#nist-standardization)
- [Algorithms Used in PQC-VPN](#algorithms-used-in-pqc-vpn)
- [Algorithm Comparison](#algorithm-comparison)
- [Implementation Details](#implementation-details)
- [Security Considerations](#security-considerations)
- [Performance Analysis](#performance-analysis)
- [Migration Strategy](#migration-strategy)

## Introduction to Post-Quantum Cryptography

### The Quantum Threat

Current cryptographic systems rely on mathematical problems that are hard for classical computers but vulnerable to quantum computers:

- **RSA**: Based on integer factorization (vulnerable to Shor's algorithm)
- **ECDSA**: Based on discrete logarithm problem (vulnerable to Shor's algorithm)  
- **Diffie-Hellman**: Based on discrete logarithm problem (vulnerable to Shor's algorithm)

### Why PQC Matters

Post-Quantum Cryptography provides algorithms believed to be secure against both classical and quantum computers:

- **Quantum-resistant**: Secure against known quantum algorithms
- **Future-proof**: Protection against emerging quantum threats
- **Performance**: Optimized for practical deployment
- **Standardized**: NIST-approved algorithms for enterprise use

## NIST Standardization

### NIST PQC Competition

The National Institute of Standards and Technology (NIST) ran a multi-year process to standardize post-quantum cryptographic algorithms:

- **Round 1 (2017)**: 69 candidate algorithms
- **Round 2 (2019)**: 26 algorithms advanced
- **Round 3 (2020)**: 15 algorithms for final evaluation
- **Standards (2022-2024)**: Selected algorithms published as standards

### Selected Standards

#### Primary Standards (2022)
- **CRYSTALS-Kyber**: Key encapsulation mechanism
- **CRYSTALS-Dilithium**: Digital signatures
- **FALCON**: Compact digital signatures
- **SPHINCS+**: Stateless hash-based signatures

#### Additional Standards (2024)
- **ML-KEM** (Kyber): FIPS 203 standard
- **ML-DSA** (Dilithium): FIPS 204 standard
- **SLH-DSA** (SPHINCS+): FIPS 205 standard

## Algorithms Used in PQC-VPN

### Key Encapsulation Mechanisms (KEM)

#### CRYSTALS-Kyber (ML-KEM)

**Purpose**: Key establishment for symmetric encryption

**Mathematical Foundation**: Module Learning With Errors (M-LWE)

**Security Levels**:
- **Kyber-512** (NIST Level 1): Equivalent to AES-128
- **Kyber-768** (NIST Level 3): Equivalent to AES-192  
- **Kyber-1024** (NIST Level 5): Equivalent to AES-256

**Key Sizes**:
```
Kyber-512:  Public Key: 800 bytes,  Secret Key: 1,632 bytes,  Ciphertext: 768 bytes
Kyber-768:  Public Key: 1,184 bytes, Secret Key: 2,400 bytes, Ciphertext: 1,088 bytes
Kyber-1024: Public Key: 1,568 bytes, Secret Key: 3,168 bytes, Ciphertext: 1,568 bytes
```

**Usage in PQC-VPN**:
```bash
# strongSwan configuration
ike=aes256gcm16-prfsha256-kyber1024!
esp=aes256gcm16-kyber1024!
```

### Digital Signature Algorithms

#### CRYSTALS-Dilithium (ML-DSA)

**Purpose**: Authentication and non-repudiation

**Mathematical Foundation**: Module Learning With Errors (M-LWE) and Fiat-Shamir

**Security Levels**:
- **Dilithium-2** (NIST Level 1): Equivalent to AES-128
- **Dilithium-3** (NIST Level 3): Equivalent to AES-192
- **Dilithium-5** (NIST Level 5): Equivalent to AES-256

**Key and Signature Sizes**:
```
Dilithium-2: Public Key: 1,312 bytes, Secret Key: 2,528 bytes, Signature: 2,420 bytes
Dilithium-3: Public Key: 1,952 bytes, Secret Key: 4,000 bytes, Signature: 3,293 bytes  
Dilithium-5: Public Key: 2,592 bytes, Secret Key: 4,864 bytes, Signature: 4,595 bytes
```

**Usage in PQC-VPN**:
```bash
# Certificate generation
openssl genpkey -algorithm dilithium5 -out private-key.pem
openssl req -new -x509 -key private-key.pem -out certificate.pem
```

#### FALCON

**Purpose**: Compact digital signatures

**Mathematical Foundation**: NTRU lattices and GPV signatures

**Advantages**:
- **Compact signatures**: Smaller than Dilithium
- **Fast verification**: Efficient for constrained devices
- **Constant-time**: Side-channel resistant implementation

**Key and Signature Sizes**:
```
FALCON-512:  Public Key: 897 bytes,  Secret Key: 1,281 bytes, Signature: 690 bytes
FALCON-1024: Public Key: 1,793 bytes, Secret Key: 2,305 bytes, Signature: 1,330 bytes
```

#### SPHINCS+

**Purpose**: Stateless hash-based signatures

**Mathematical Foundation**: Hash functions and Merkle trees

**Advantages**:
- **Conservative security**: Based only on hash function security
- **Stateless**: No secret state to protect
- **Long-term security**: Minimal assumptions

**Variants**:
- **SPHINCS+-SHA256**: Using SHA-256 hash function
- **SPHINCS+-SHAKE**: Using SHAKE (SHA-3) hash function
- **Different parameter sets**: Trading signature size vs. speed

### Symmetric Cryptography

#### AES-GCM

**Purpose**: Bulk data encryption and authentication

**Quantum Resistance**: 
- **AES-128**: Reduced to ~64-bit security against quantum (Grover's algorithm)
- **AES-256**: Reduced to ~128-bit security against quantum
- **Recommendation**: Use AES-256 for quantum resistance

**Usage in PQC-VPN**:
```bash
# ESP (Encapsulating Security Payload)
esp=aes256gcm16-kyber1024!
```

#### SHA-3 (Keccak)

**Purpose**: Cryptographic hashing

**Quantum Resistance**: Hash functions are generally quantum-resistant for appropriate output sizes

**Usage**: 
- Certificate fingerprints
- Key derivation functions
- Message authentication

## Algorithm Comparison

### Security Levels

| Algorithm | NIST Level | Classical Security | Quantum Security | Standard |
|-----------|------------|-------------------|------------------|----------|
| Kyber-512 | 1 | 128-bit | 128-bit | FIPS 203 |
| Kyber-768 | 3 | 192-bit | 192-bit | FIPS 203 |
| Kyber-1024 | 5 | 256-bit | 256-bit | FIPS 203 |
| Dilithium-2 | 1 | 128-bit | 128-bit | FIPS 204 |
| Dilithium-3 | 3 | 192-bit | 192-bit | FIPS 204 |
| Dilithium-5 | 5 | 256-bit | 256-bit | FIPS 204 |
| FALCON-512 | 1 | 128-bit | 128-bit | - |
| FALCON-1024 | 5 | 256-bit | 256-bit | - |

### Performance Comparison

#### Key Generation (operations/second)

| Algorithm | Level 1 | Level 3 | Level 5 |
|-----------|---------|---------|---------|
| Kyber | 24,000 | 17,000 | 12,000 |
| Dilithium | 1,200 | 800 | 600 |
| FALCON | 300 | - | 150 |
| RSA-2048 | 500 | - | - |
| ECDSA P-256 | 15,000 | - | - |

#### Signature Generation (operations/second)

| Algorithm | Level 1 | Level 3 | Level 5 |
|-----------|---------|---------|---------|
| Dilithium | 3,000 | 2,200 | 1,600 |
| FALCON | 8,000 | - | 4,500 |
| SPHINCS+ | 50 | 30 | 20 |
| RSA-2048 | 1,500 | - | - |
| ECDSA P-256 | 25,000 | - | - |

#### Verification (operations/second)

| Algorithm | Level 1 | Level 3 | Level 5 |
|-----------|---------|---------|---------|
| Dilithium | 4,500 | 3,200 | 2,400 |
| FALCON | 25,000 | - | 15,000 |
| SPHINCS+ | 30,000 | 20,000 | 15,000 |
| RSA-2048 | 25,000 | - | - |
| ECDSA P-256 | 10,000 | - | - |

*Performance figures are approximate and vary by implementation and hardware*

## Implementation Details

### liboqs Integration

PQC-VPN uses the Open Quantum Safe (OQS) project's liboqs library:

```c
// Example key generation with liboqs
#include <oqs/oqs.h>

OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_1024);
uint8_t public_key[OQS_KEM_kyber_1024_length_public_key];
uint8_t secret_key[OQS_KEM_kyber_1024_length_secret_key];

OQS_KEM_keypair(kem, public_key, secret_key);
```

### strongSwan Configuration

Algorithm specification in strongSwan:

```bash
# IKE (Internet Key Exchange) algorithms
ike = aes256gcm16-prfsha256-kyber1024!

# ESP (Encapsulating Security Payload) algorithms  
esp = aes256gcm16-kyber1024!

# Authentication
authby = pubkey
leftcert = dilithium5-cert.pem
```

### OpenSSL Integration

Certificate operations with OpenSSL:

```bash
# Generate Dilithium private key
openssl genpkey -algorithm dilithium5 -out ca-key.pem

# Generate certificate request
openssl req -new -key user-key.pem -out user.csr

# Sign certificate
openssl x509 -req -in user.csr -CA ca-cert.pem -CAkey ca-key.pem -out user-cert.pem
```

## Security Considerations

### Algorithm Selection Criteria

1. **Security Level**: Choose appropriate NIST security level
2. **Performance Requirements**: Balance security vs. speed
3. **Resource Constraints**: Consider memory and bandwidth limitations
4. **Compliance**: Meet regulatory requirements
5. **Future-proofing**: Plan for algorithm evolution

### Recommended Configurations

#### High Security (Government/Military)
```yaml
algorithms:
  kem: kyber1024
  signature: dilithium5
  symmetric: aes256gcm
  hash: sha3-256
```

#### Balanced (Enterprise)
```yaml
algorithms:
  kem: kyber768
  signature: dilithium3
  symmetric: aes256gcm
  hash: sha256
```

#### Performance-Optimized (IoT/Mobile)
```yaml
algorithms:
  kem: kyber512
  signature: dilithium2
  symmetric: aes128gcm
  hash: sha256
```

### Security Best Practices

1. **Hybrid Deployment**: Combine PQC with classical algorithms during transition
2. **Crypto-Agility**: Design systems to easily update algorithms
3. **Regular Updates**: Keep cryptographic libraries current
4. **Side-Channel Protection**: Use constant-time implementations
5. **Forward Secrecy**: Ensure perfect forward secrecy (PFS)

### Known Limitations

1. **Larger Key Sizes**: PQC keys are larger than classical keys
2. **Implementation Maturity**: Newer algorithms may have implementation issues
3. **Performance Impact**: Some algorithms are slower than classical counterparts
4. **Bandwidth Overhead**: Larger certificates and signatures increase bandwidth usage

## Performance Analysis

### Network Overhead

#### Certificate Sizes

| Algorithm | Certificate Size | Classical Equivalent |
|-----------|------------------|---------------------|
| RSA-2048 | ~1.2 KB | 1.0x |
| ECDSA P-256 | ~0.5 KB | 1.0x |
| Dilithium-2 | ~3.5 KB | 3.0x |
| Dilithium-3 | ~5.2 KB | 4.5x |
| Dilithium-5 | ~7.1 KB | 6.0x |
| FALCON-512 | ~2.8 KB | 2.4x |
| FALCON-1024 | ~4.2 KB | 3.6x |

#### Handshake Overhead

PQC impact on VPN handshake:

```
Classical (RSA/ECDSA):
- IKE messages: ~2-3 KB total
- Handshake time: ~50-100ms

PQC (Kyber/Dilithium):
- IKE messages: ~8-12 KB total  
- Handshake time: ~80-150ms
- Overhead: 3-4x size, 1.5-2x time
```

### CPU Performance Impact

Typical CPU overhead for PQC operations:

```
Operation         | Classical | Dilithium-3 | Overhead
Key Generation    | 0.1ms     | 0.5ms       | 5x
Signing          | 0.05ms    | 0.3ms       | 6x
Verification     | 0.02ms    | 0.1ms       | 5x
```

### Memory Requirements

Additional memory usage:

```
Component              | Classical | PQC      | Increase
Certificate Storage    | 1 KB      | 5 KB     | 5x
Private Key Storage    | 0.3 KB    | 4 KB     | 13x
Runtime Buffers        | 2 KB      | 8 KB     | 4x
```

## Migration Strategy

### Hybrid Transition

Recommended approach for migrating to PQC:

#### Phase 1: Dual Algorithm Support
```bash
# Support both classical and PQC
ike=aes256gcm16-prfsha256-kyber1024,aes256gcm16-prfsha256-modp2048!
```

#### Phase 2: PQC Preferred
```bash
# Prefer PQC but fallback to classical
ike=aes256gcm16-prfsha256-kyber1024!,aes256gcm16-prfsha256-modp2048
```

#### Phase 3: PQC Only
```bash
# Pure PQC deployment
ike=aes256gcm16-prfsha256-kyber1024!
```

### Migration Timeline

Suggested timeline for PQC adoption:

```
Year 1 (2024-2025): Testing and Pilot Deployments
- Lab testing of PQC algorithms
- Small-scale pilot with trusted users
- Performance benchmarking

Year 2 (2025-2026): Hybrid Deployment
- Dual algorithm support in production
- Gradual user migration
- Monitoring and optimization

Year 3 (2026-2027): PQC Majority
- Most users on PQC algorithms
- Classical algorithms for legacy systems
- Full feature parity

Year 4+ (2027+): PQC Standard
- Default to PQC algorithms
- Classical algorithms deprecated
- Quantum-safe by default
```

### Implementation Checklist

- [ ] **Assessment**: Evaluate current cryptographic inventory
- [ ] **Planning**: Develop migration timeline and milestones
- [ ] **Testing**: Validate PQC algorithms in test environment
- [ ] **Infrastructure**: Upgrade systems to support larger keys/certificates
- [ ] **Training**: Educate staff on PQC concepts and tools
- [ ] **Deployment**: Gradual rollout with monitoring
- [ ] **Validation**: Verify security and performance targets
- [ ] **Documentation**: Update procedures and configurations

## Future Considerations

### Algorithm Evolution

- **NIST Round 4**: Additional algorithms under consideration
- **Performance Improvements**: Optimized implementations
- **New Variants**: Algorithm parameter updates
- **Quantum Advances**: Response to quantum computing progress

### Standards Development

- **IETF Integration**: PQC in internet protocols
- **Industry Adoption**: Vendor support and interoperability
- **Compliance**: Regulatory requirements and certifications
- **Best Practices**: Community guidelines and recommendations

### Technology Trends

- **Hardware Acceleration**: Specialized PQC processors
- **Cloud Integration**: PQC in cloud services
- **Mobile Optimization**: PQC for mobile and IoT devices
- **Quantum Networks**: Integration with quantum key distribution

---

This document provides the foundation for understanding and implementing Post-Quantum Cryptography in PQC-VPN. Regular updates will ensure alignment with evolving standards and best practices.