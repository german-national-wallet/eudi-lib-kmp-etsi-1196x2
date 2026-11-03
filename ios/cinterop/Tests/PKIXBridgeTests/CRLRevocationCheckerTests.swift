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

import XCTest
@testable import PKIXBridge

/// Fixtures: `crl-test-ca` (CA), `crl-test-valid-leaf` and `crl-test-revoked-leaf` (both with a CRL
/// distribution point https://crl.example.test/ca.crl) and `crl-test-ca.crl`, which revokes the revoked
/// leaf and carries a critical Issuing Distribution Point scoped to that URL and to user certificates.
final class CRLRevocationCheckerTests: XCTestCase {

    private func fixture(_ name: String, _ ext: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext) else {
            throw XCTSkip("Fixture \(name).\(ext) not found")
        }
        return try Data(contentsOf: url)
    }

    private func validate(
        leaf leafName: String = "crl-test-valid-leaf",
        fetch: @escaping (URL) throws -> Data,
        now: Date? = nil
    ) throws -> Error? {
        let leaf = try fixture(leafName, "der")
        let anchor = try fixture("crl-test-ca", "der")
        let crlData = try fixture("crl-test-ca", "crl")
        let current = try now ?? CertificateRevocationList.parse(crlData).thisUpdate.addingTimeInterval(60)
        let validator = PKIXValidator(
            configuration: PKIXConfiguration(isRevocationEnabled: true, revocationMethod: .crl),
            crlChecker: CRLRevocationChecker(fetch: fetch, now: { current })
        )
        let expect = expectation(description: "completion")
        var failure: Error?
        validator.validateCertificateChain(
            leafCertificate: leaf as NSData,
            intermediateCertificates: [],
            trustAnchors: [anchor as NSData]
        ) { _, error in
            failure = error
            expect.fulfill()
        }
        wait(for: [expect], timeout: 10)
        return failure
    }

    private func underlyingMessage(_ error: Error?) -> String {
        guard let error = error as NSError? else { return "nil" }
        return (error.userInfo[NSUnderlyingErrorKey] as? Error).map { "\($0)" } ?? error.localizedDescription
    }

    func test_crlParse_readsIssuerValidityRevokedSerialsAndIssuingDistributionPoint() throws {
        let crl = try CertificateRevocationList.parse(try fixture("crl-test-ca", "crl"))
        XCTAssertEqual(crl.issuer.value(forOid: "2.5.4.3"), "CRL Test CA")
        XCTAssertNotNil(crl.nextUpdate)
        XCTAssertEqual(crl.revokedSerials.count, 1)
        XCTAssertEqual(crl.signatureAlgorithmOid, "1.2.840.10045.4.3.2")
        XCTAssertTrue(crl.criticalExtensionOids.isEmpty, "a critical Issuing Distribution Point is understood")
        let idp = try XCTUnwrap(crl.issuingDistributionPoint)
        XCTAssertEqual(idp.uris, ["https://crl.example.test/ca.crl"])
        XCTAssertTrue(idp.onlyContainsUserCerts)
        XCTAssertFalse(idp.hasUnsupportedScope)
    }

    func test_issuingDistributionPoint_scope() throws {
        let idp = try XCTUnwrap(CertificateRevocationList.parse(try fixture("crl-test-ca", "crl")).issuingDistributionPoint)
        let url = try XCTUnwrap(URL(string: "https://crl.example.test/ca.crl"))
        XCTAssertNoThrow(try idp.checkScope(url: url, certificateIsCA: false))
        XCTAssertThrowsError(try idp.checkScope(url: url, certificateIsCA: true))
        XCTAssertThrowsError(try idp.checkScope(url: try XCTUnwrap(URL(string: "https://example.test/other.crl")), certificateIsCA: false))
    }

    func test_crl_notRevokedLeafWithValidCrl_isTrusted() throws {
        let crlData = try fixture("crl-test-ca", "crl")
        let error = try validate(fetch: { _ in crlData })
        XCTAssertNil(error, underlyingMessage(error))
    }

    func test_crl_revokedLeaf_isNotTrusted() throws {
        let crlData = try fixture("crl-test-ca", "crl")
        let error = try validate(leaf: "crl-test-revoked-leaf", fetch: { _ in crlData })
        XCTAssertNotNil(error)
        XCTAssertTrue(underlyingMessage(error).contains("revoked"), underlyingMessage(error))
    }

    func test_crl_downloadFailure_isNotTrusted() throws {
        XCTAssertNotNil(try validate(fetch: { _ in throw URLError(.notConnectedToInternet) }))
    }

    func test_crl_tamperedCrl_isNotTrusted() throws {
        var crlData = try fixture("crl-test-ca", "crl")
        crlData[crlData.count - 1] ^= 0xFF
        XCTAssertNotNil(try validate(fetch: { _ in crlData }))
    }

    func test_crl_expiredCrl_isNotTrusted() throws {
        let crlData = try fixture("crl-test-ca", "crl")
        let nextUpdate = try XCTUnwrap(CertificateRevocationList.parse(crlData).nextUpdate)
        XCTAssertNotNil(try validate(fetch: { _ in crlData }, now: nextUpdate.addingTimeInterval(60)))
    }

    func test_crl_signerIsTheTrustAnchor_isTrustedWithoutFetching() throws {
        var fetched = false
        let error = try validate(leaf: "crl-test-ca", fetch: { _ in
            fetched = true
            throw URLError(.notConnectedToInternet)
        })
        XCTAssertNil(error, underlyingMessage(error))
        XCTAssertFalse(fetched, "a trust anchor must not be revocation-checked")
    }
}
