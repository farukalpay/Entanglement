import Foundation
import CryptoKit
import RuntimeKit

func expect(_ condition: @autoclosure () -> Bool, _ message: String) {
    if !condition() {
        fputs("FAIL: \(message)\n", stderr)
        exit(1)
    }
}

let unavailableGraph = VerifiedGraph.example(requiresPrivateANE: true)
let unavailableRuntime = RuntimeGraph(
    graph: unavailableGraph,
    ane: PrivateANEBackend(forceUnavailable: true)
)
let unavailableReport = unavailableRuntime.realize()
expect(unavailableReport.status == .isolated, "private ANE unavailability must isolate branch")
expect(
    unavailableReport.instabilities.first?.kind == .backendInadmissible,
    "private ANE unavailability must become backend instability"
)
expect(
    unavailableReport.instabilities.first?.evidence.contains("_ANE") == true,
    "instability evidence must name private ANE boundary"
)

let replayGraph = VerifiedGraph.example(requiresPrivateANE: false)
let replayRuntime = RuntimeGraph(graph: replayGraph, ane: PrivateANEBackend(forceUnavailable: true))
let first = replayRuntime.realize()
let second = replayRuntime.replay(first.trace)
expect(first.trace.digest == second.trace.digest, "replay digest must be deterministic")
expect(second.status == .realized, "replay without ANE must realize")

let bundleURL = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("entanglement-runtime-manifest")
try? FileManager.default.removeItem(at: bundleURL)
try FileManager.default.createDirectory(at: bundleURL, withIntermediateDirectories: true)
let graphManifest = """
{
  "world": "CapabilityStore",
  "requires_private_ane": true,
  "nodes": [
    { "id": "put", "backend": "metal", "differentiable": true },
    { "id": "secure_eval", "backend": "private-ane", "differentiable": false }
  ]
}
"""
try Data(graphManifest.utf8).write(to: bundleURL.appendingPathComponent("graph.json"))
try Data("{\"schema_version\":3,\"world\":\"CapabilityStore\"}\n".utf8)
    .write(to: bundleURL.appendingPathComponent("cert.json"))
try Data("{\"resources\":[]}\n".utf8)
    .write(to: bundleURL.appendingPathComponent("resource_layout.json"))
let artifactFiles = ["graph.json", "cert.json", "resource_layout.json"]
let artifactChecksums = try artifactFiles.reduce(into: [String: String]()) { rows, file in
    let data = try Data(contentsOf: bundleURL.appendingPathComponent(file))
    rows[file] = "sha256:\(sha256Hex(data))"
}
let manifestObject: [String: Any] = [
    "schema_version": 3,
    "target": ["platform": "apple-silicon-macos"],
    "artifact_checksums": artifactChecksums,
    "backend_capabilities": [
        ["node": "put", "capability": "metal"],
        ["node": "secure_eval", "capability": "private-ane"],
    ],
]
let manifestData = try JSONSerialization.data(withJSONObject: manifestObject, options: [.prettyPrinted, .sortedKeys])
try manifestData.write(to: bundleURL.appendingPathComponent("manifest.json"))
var checksumRows = artifactChecksums.map { file, digest in
    "\(digest.replacingOccurrences(of: "sha256:", with: ""))  \(file)"
}
checksumRows.append("\(sha256Hex(manifestData))  manifest.json")
try Data((checksumRows.sorted().joined(separator: "\n") + "\n").utf8)
    .write(to: bundleURL.appendingPathComponent("checksums.sha256"))
let loadedGraph = try VerifiedGraph.load(bundlePath: bundleURL.path)
expect(loadedGraph.requiresPrivateANE, "manifest must declare private ANE requirement explicitly")
expect(loadedGraph.nodes[1].backend == "private-ane", "runtime must read backend rows without name heuristics")

let metal = MetalBackend().probeSharedBuffer(byteCount: 1024)
if metal.available {
    expect(metal.trace == "shared-buffer-ok", "Metal shared buffer probe must record successful trace")
}

print("RuntimeKit self-test PASS")

func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
