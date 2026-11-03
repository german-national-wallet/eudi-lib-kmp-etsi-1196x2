/*
 * Copyright (c) 2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Foundation
import Security

/// Checks every non-anchor certificate of a validated path against the CRLs named in its
/// CRL Distribution Points extension.
///
/// Security.framework does not report a positive revocation result from a CRL, so a CRL-only
/// chain evaluated with `kSecRevocationRequirePositiveResponse` is never trusted. The chain is
/// therefore evaluated by SecTrust without a revocation policy and checked here afterwards.
/// The check fails closed: a certificate without a usable CRL is treated as not trusted.
internal final class CRLRevocationChecker {

    struct Failure: LocalizedError {
        let reason: String
        var errorDescription: String? { reason }
    }

    private let fetch: (URL) throws -> Data
    private let now: () -> Date
    private let lock = NSLock()
    private var cache: [URL: CertificateRevocationList] = [:]

    init(fetch: @escaping (URL) throws -> Data = CRLRevocationChecker.download, now: @escaping () -> Date = Date.init) {
        self.fetch = fetch
        self.now = now
    }

    /// - Parameter chain: the path built by SecTrust, leaf first and trust anchor last. The trust
    ///   anchor itself is never checked (RFC 5280 6.1), so a path holding only the anchor passes.
    func check(chain: [SecCertificate]) throws {
        guard !chain.isEmpty else { throw Failure(reason: "CRL check needs a certificate path") }
        for index in 0..<(chain.count - 1) {
            try check(certificate: chain[index], issuer: chain[index + 1])
        }
    }

    private func check(certificate: SecCertificate, issuer: SecCertificate) throws {
        let parsed = try X509Parser.parse(SecCertificateCopyData(certificate) as Data)
        let issuerParsed = try X509Parser.parse(SecCertificateCopyData(issuer) as Data)
        guard let extensionValue = parsed.findExtension(oid: X509Oids.crlDistributionPoints)?.valueBytes else {
            throw Failure(reason: "Certificate \(parsed.subject) has no CRL distribution point")
        }
        let urls = try X509ExtensionDecoder.decodeCrlDistributionPoints(extensionValue)
            .compactMap(URL.init(string:))
            .filter { ["http", "https"].contains($0.scheme?.lowercased()) }
        guard !urls.isEmpty else {
            throw Failure(reason: "Certificate \(parsed.subject) has no HTTP CRL distribution point")
        }
        let serial = Self.normalizedSerial(parsed.serialNumber)
        let isCA = try parsed.findExtension(oid: X509Oids.basicConstraints)
            .map { try X509ExtensionDecoder.decodeBasicConstraints($0.valueBytes).isCa } ?? false
        var lastError: Error?
        for url in urls {
            let crl: CertificateRevocationList
            do {
                crl = try revocationList(at: url, issuer: issuer, issuerName: issuerParsed.subject)
                try crl.issuingDistributionPoint?.checkScope(url: url, certificateIsCA: isCA)
            } catch {
                lastError = error
                continue
            }
            if crl.revokedSerials.contains(serial) {
                throw Failure(reason: "Certificate \(parsed.subject) is revoked (CRL \(url.absoluteString))")
            }
            return
        }
        throw lastError ?? Failure(reason: "No usable CRL for \(parsed.subject)")
    }

    private func revocationList(at url: URL, issuer: SecCertificate, issuerName: X509DistinguishedName) throws -> CertificateRevocationList {
        let currentDate = now()
        lock.lock()
        let cached = cache[url]
        lock.unlock()
        if let cached, cached.issuer == issuerName, cached.isCurrent(at: currentDate) {
            return cached
        }
        let crl = try CertificateRevocationList.parse(try fetch(url))
        guard crl.issuer == issuerName else {
            throw Failure(reason: "CRL \(url.absoluteString) is issued by \(crl.issuer), expected \(issuerName)")
        }
        guard crl.criticalExtensionOids.isEmpty else {
            throw Failure(reason: "CRL \(url.absoluteString) has unsupported critical extensions \(crl.criticalExtensionOids)")
        }
        guard crl.isCurrent(at: currentDate) else {
            throw Failure(reason: "CRL \(url.absoluteString) is outside its validity period")
        }
        try crl.verifySignature(issuer: issuer)
        lock.lock()
        cache[url] = crl
        lock.unlock()
        return crl
    }

    static func normalizedSerial(_ bytes: Data) -> Data {
        Data(bytes.drop(while: { $0 == 0 }))
    }

    static func download(_ url: URL) throws -> Data {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        request.httpMethod = "GET"
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Data, Error> = .failure(Failure(reason: "CRL download from \(url.absoluteString) did not complete"))
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error {
                result = .failure(error)
            } else if let status = (response as? HTTPURLResponse)?.statusCode, status != 200 {
                result = .failure(Failure(reason: "CRL download from \(url.absoluteString) returned HTTP \(status)"))
            } else if let data {
                result = .success(data)
            }
            semaphore.signal()
        }.resume()
        semaphore.wait()
        return try result.get()
    }
}

internal struct CertificateRevocationList {
    let issuer: X509DistinguishedName
    let thisUpdate: Date
    let nextUpdate: Date?
    let revokedSerials: Set<Data>
    let issuingDistributionPoint: IssuingDistributionPoint?
    let criticalExtensionOids: [String]
    let tbsBytes: Data
    let signatureAlgorithmOid: String
    let signature: Data

    func isCurrent(at date: Date) -> Bool {
        guard let nextUpdate else { return false }
        return thisUpdate <= date && date <= nextUpdate
    }

    func verifySignature(issuer: SecCertificate) throws {
        guard let key = SecCertificateCopyKey(issuer) else {
            throw CRLRevocationChecker.Failure(reason: "CRL issuer key cannot be read")
        }
        guard let algorithm = Self.signatureAlgorithms[signatureAlgorithmOid] else {
            throw CRLRevocationChecker.Failure(reason: "Unsupported CRL signature algorithm \(signatureAlgorithmOid)")
        }
        var error: Unmanaged<CFError>?
        guard SecKeyVerifySignature(key, algorithm, tbsBytes as CFData, signature as CFData, &error) else {
            throw CRLRevocationChecker.Failure(reason: "CRL signature is invalid")
        }
    }

    private static let signatureAlgorithms: [String: SecKeyAlgorithm] = [
        "1.2.840.10045.4.3.2": .ecdsaSignatureMessageX962SHA256,
        "1.2.840.10045.4.3.3": .ecdsaSignatureMessageX962SHA384,
        "1.2.840.10045.4.3.4": .ecdsaSignatureMessageX962SHA512,
        "1.2.840.113549.1.1.11": .rsaSignatureMessagePKCS1v15SHA256,
        "1.2.840.113549.1.1.12": .rsaSignatureMessagePKCS1v15SHA384,
        "1.2.840.113549.1.1.13": .rsaSignatureMessagePKCS1v15SHA512
    ]

    /// CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue BIT STRING } (RFC 5280 5.1)
    static func parse(_ data: Data) throws -> CertificateRevocationList {
        let der = try derBytes(data)
        let top = try ASN1Parser.parse(der).sequence()
        guard top.count == 3 else { throw ASN1Error.invalidPrimitive(reason: "CertificateList must have 3 elements") }
        guard let tbsBytes = firstChildTLV(of: der) else { throw ASN1Error.invalidPrimitive(reason: "Missing tbsCertList") }

        let tbs = try top[0].sequence()
        var idx = 0
        if idx < tbs.count, tbs[idx].isUniversal(ASN1UniversalTag.integer) { idx += 1 }
        idx += 1 // signature AlgorithmIdentifier, repeated in signatureAlgorithm
        guard idx < tbs.count else { throw ASN1Error.invalidPrimitive(reason: "Missing CRL issuer") }
        let issuer = try X509Parser.parseName(tbs[idx]); idx += 1
        guard idx < tbs.count else { throw ASN1Error.invalidPrimitive(reason: "Missing thisUpdate") }
        let thisUpdate = try tbs[idx].anyTime(); idx += 1
        var nextUpdate: Date?
        if idx < tbs.count, tbs[idx].isUniversal(ASN1UniversalTag.utcTime) || tbs[idx].isUniversal(ASN1UniversalTag.generalizedTime) {
            nextUpdate = try tbs[idx].anyTime(); idx += 1
        }
        var revokedSerials = Set<Data>()
        if idx < tbs.count, tbs[idx].isUniversal(ASN1UniversalTag.sequence) {
            for entry in try tbs[idx].sequence() {
                guard let serial = try entry.sequence().first else { continue }
                revokedSerials.insert(CRLRevocationChecker.normalizedSerial(try serial.integerBytes()))
            }
            idx += 1
        }
        var criticalExtensionOids: [String] = []
        var issuingDistributionPoint: IssuingDistributionPoint?
        if idx < tbs.count, tbs[idx].isContextSpecific(0), let wrapped = try tbs[idx].requireConstructed().first {
            for ext in try wrapped.sequence() {
                let fields = try ext.sequence()
                guard let oidElement = fields.first, let valueElement = fields.last else { continue }
                let oid = try oidElement.objectIdentifier()
                let critical = fields.count == 3 ? try fields[1].bool() : false
                if oid == IssuingDistributionPoint.oid {
                    issuingDistributionPoint = try IssuingDistributionPoint.parse(try valueElement.octetString())
                } else if critical {
                    criticalExtensionOids.append(oid)
                }
            }
        }

        guard let algorithmOid = try top[1].sequence().first?.objectIdentifier() else {
            throw ASN1Error.invalidPrimitive(reason: "Missing CRL signature algorithm")
        }
        return CertificateRevocationList(
            issuer: issuer,
            thisUpdate: thisUpdate,
            nextUpdate: nextUpdate,
            revokedSerials: revokedSerials,
            issuingDistributionPoint: issuingDistributionPoint,
            criticalExtensionOids: criticalExtensionOids,
            tbsBytes: tbsBytes,
            signatureAlgorithmOid: algorithmOid,
            signature: try top[2].bitString().data
        )
    }

    /// Accepts DER or a PEM `X509 CRL` block.
    private static func derBytes(_ data: Data) throws -> Data {
        guard let text = String(data: data, encoding: .ascii), text.contains("-----BEGIN") else { return data }
        let body = text.components(separatedBy: .newlines).filter { !$0.hasPrefix("-----") }.joined()
        guard let der = Data(base64Encoded: body) else { throw ASN1Error.invalidPrimitive(reason: "Invalid PEM CRL") }
        return der
    }

    /// The raw TLV bytes of the first element inside the outer SEQUENCE, needed to verify the signature.
    private static func firstChildTLV(of der: Data) -> Data? {
        let bytes = [UInt8](der)
        guard let (_, outerHeader) = lengthAndHeader(bytes, at: 0),
              let (innerLength, innerHeader) = lengthAndHeader(bytes, at: outerHeader) else { return nil }
        let end = outerHeader + innerHeader + innerLength
        guard end <= bytes.count else { return nil }
        return Data(bytes[outerHeader..<end])
    }

    private static func lengthAndHeader(_ bytes: [UInt8], at offset: Int) -> (length: Int, header: Int)? {
        guard offset + 1 < bytes.count else { return nil }
        let first = bytes[offset + 1]
        if first & 0x80 == 0 { return (Int(first), 2) }
        let count = Int(first & 0x7F)
        guard count > 0, count <= 4, offset + 1 + count < bytes.count else { return nil }
        var length = 0
        for index in 0..<count { length = (length << 8) | Int(bytes[offset + 2 + index]) }
        return (length, 2 + count)
    }
}

/// IssuingDistributionPoint ::= SEQUENCE { distributionPoint [0], onlyContainsUserCerts [1],
/// onlyContainsCACerts [2], onlySomeReasons [3], indirectCRL [4], onlyContainsAttributeCerts [5] } (RFC 5280 5.2.5)
internal struct IssuingDistributionPoint {
    static let oid = "2.5.29.28"

    let uris: [String]
    let onlyContainsUserCerts: Bool
    let onlyContainsCACerts: Bool
    /// Partial (onlySomeReasons), indirect and attribute-certificate CRLs cannot prove a certificate is not revoked here.
    let hasUnsupportedScope: Bool

    static func parse(_ value: Data) throws -> IssuingDistributionPoint {
        var uris: [String] = []
        var onlyUser = false
        var onlyCA = false
        var unsupported = false
        for field in try ASN1Parser.parse(value).sequence() {
            let isTrue = field.primitiveBytes?.first == 0xFF
            switch field.tag {
            case .contextSpecific(0):
                for name in field.children ?? [] {
                    guard case .contextSpecific(0) = name.tag else {
                        unsupported = true
                        continue
                    }
                    for generalName in name.children ?? [] {
                        if case .contextSpecific(6) = generalName.tag, let bytes = generalName.primitiveBytes,
                           let uri = String(data: bytes, encoding: .ascii) {
                            uris.append(uri)
                        }
                    }
                }
            case .contextSpecific(1): onlyUser = isTrue
            case .contextSpecific(2): onlyCA = isTrue
            case .contextSpecific(3): unsupported = true
            case .contextSpecific(4), .contextSpecific(5): if isTrue { unsupported = true }
            default: unsupported = true
            }
        }
        return IssuingDistributionPoint(uris: uris, onlyContainsUserCerts: onlyUser, onlyContainsCACerts: onlyCA, hasUnsupportedScope: unsupported)
    }

    func checkScope(url: URL, certificateIsCA: Bool) throws {
        if hasUnsupportedScope {
            throw CRLRevocationChecker.Failure(reason: "CRL \(url.absoluteString) is a partial, indirect or attribute CRL")
        }
        if !uris.isEmpty, !uris.contains(url.absoluteString) {
            throw CRLRevocationChecker.Failure(reason: "CRL \(url.absoluteString) is scoped to another distribution point \(uris)")
        }
        if onlyContainsUserCerts, certificateIsCA {
            throw CRLRevocationChecker.Failure(reason: "CRL \(url.absoluteString) only covers end-entity certificates")
        }
        if onlyContainsCACerts, !certificateIsCA {
            throw CRLRevocationChecker.Failure(reason: "CRL \(url.absoluteString) only covers CA certificates")
        }
    }
}
