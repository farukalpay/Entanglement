import CryptoKit
import Foundation
import RuntimeKit
import XCTest

final class RuntimeKitTests: XCTestCase {
    func testManifestAndChecksumsAreRequired() throws {
        let bundle = try makeTemporaryBundle()
        try writeJSON(["world": "MissingManifest", "requires_private_ane": false, "nodes": []], to: bundle.appendingPathComponent("graph.json"))

        XCTAssertThrowsError(try VerifiedGraph.load(bundlePath: bundle.path)) { error in
            XCTAssertEqual(error as? RuntimeLoadError, .missingManifest(bundle.appendingPathComponent("manifest.json").path))
        }
    }

    func testTamperedGraphIsRejectedBeforeRuntimeRealization() throws {
        let bundle = try makeVerifiedBundle(requiresPrivateANE: false)
        try Data("tampered".utf8).write(to: bundle.appendingPathComponent("graph.json"))

        XCTAssertThrowsError(try VerifiedGraph.load(bundlePath: bundle.path)) { error in
            XCTAssertEqual(error as? RuntimeLoadError, .checksumMismatch("graph.json"))
        }
    }

    func testPrivateAneRemainsFirstClassAndFailsClosedWhenUnavailable() throws {
        let bundle = try makeVerifiedBundle(requiresPrivateANE: true)
        let graph = try VerifiedGraph.load(bundlePath: bundle.path)

        XCTAssertTrue(graph.requiresPrivateANE)
        XCTAssertEqual(graph.nodes.last?.backend, "private-ane")

        let runtime = RuntimeGraph(graph: graph, ane: PrivateANEBackend(forceUnavailable: true), metal: MetalBackend(forceUnavailable: true))
        let report = runtime.realize()
        XCTAssertEqual(report.status, .isolated)
        XCTAssertEqual(report.instabilities.first?.kind, .backendInadmissible)
    }

    func testExternalCapabilitiesAreLoadedAndTraced() throws {
        let externalCapabilities: [[String: Any]] = [
            [
                "name": "ffi",
                "interface": "runtime_call",
                "resource": "heap",
                "access": "read",
                "admissible": true,
                "evidence": "ffi_manifest_trace",
            ],
        ]
        let bundle = try makeVerifiedBundle(
            requiresPrivateANE: false,
            externalCapabilities: externalCapabilities
        )
        let graph = try VerifiedGraph.load(bundlePath: bundle.path)

        XCTAssertEqual(graph.externalCapabilities.first?.name, "ffi")
        let runtime = RuntimeGraph(graph: graph, ane: PrivateANEBackend(forceUnavailable: true))
        let report = runtime.realize()
        XCTAssertEqual(report.status, .realized)
        XCTAssertTrue(report.trace.events.contains("external:ffi:runtime_call:heap:read"))
    }

    private func makeTemporaryBundle() throws -> URL {
        let bundle = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("entanglement-runtime-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: bundle, withIntermediateDirectories: true)
        return bundle
    }

    private func makeVerifiedBundle(
        requiresPrivateANE: Bool,
        externalCapabilities: [[String: Any]] = []
    ) throws -> URL {
        let bundle = try makeTemporaryBundle()
        let nodes: [[String: Any]] = requiresPrivateANE
            ? [
                ["id": "put", "backend": "metal", "differentiable": true],
                ["id": "secure_eval", "backend": "private-ane", "differentiable": false],
            ]
            : [["id": "eval", "backend": "cpu", "differentiable": false]]
        try writeJSON(
            [
                "world": "RuntimeFixture",
                "requires_private_ane": requiresPrivateANE,
                "nodes": nodes,
                "external_capabilities": externalCapabilities,
            ],
            to: bundle.appendingPathComponent("graph.json")
        )
        try writeJSON(["schema_version": 3, "world": "RuntimeFixture"], to: bundle.appendingPathComponent("cert.json"))
        try writeJSON(["resources": []], to: bundle.appendingPathComponent("resource_layout.json"))

        let artifactChecksums = try ["graph.json", "cert.json", "resource_layout.json"].reduce(into: [String: String]()) { rows, file in
            let data = try Data(contentsOf: bundle.appendingPathComponent(file))
            rows[file] = "sha256:\(sha256Hex(data))"
        }
        try writeJSON(
            [
                "schema_version": 3,
                "target": ["platform": "apple-silicon-macos"],
                "artifact_checksums": artifactChecksums,
                "backend_capabilities": nodes.map { ["node": $0["id"]!, "capability": $0["backend"]!] },
                "external_capabilities": externalCapabilities,
            ],
            to: bundle.appendingPathComponent("manifest.json")
        )
        var checksumRows = artifactChecksums
            .map { file, digest in "\(digest.replacingOccurrences(of: "sha256:", with: ""))  \(file)" }
        let manifestData = try Data(contentsOf: bundle.appendingPathComponent("manifest.json"))
        checksumRows.append("\(sha256Hex(manifestData))  manifest.json")
        try Data((checksumRows.sorted().joined(separator: "\n") + "\n").utf8)
            .write(to: bundle.appendingPathComponent("checksums.sha256"))
        return bundle
    }

    private func writeJSON(_ value: Any, to url: URL) throws {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
        try data.write(to: url)
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
