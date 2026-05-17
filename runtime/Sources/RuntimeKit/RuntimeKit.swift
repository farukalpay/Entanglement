import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(Metal)
import Metal
#endif

private let minimumBundleManifestSchemaVersion = 3
private let currentBundleManifestSchemaVersion = 6

public enum RuntimeStatus: Equatable {
    case realized
    case isolated
    case collapsed
}

public enum RuntimeInstabilityKind: Equatable {
    case backendInadmissible
    case externalInadmissible
    case invariantDrift
    case numericDivergence
    case resourceConflict
}

public struct RuntimeInstability: Equatable {
    public let kind: RuntimeInstabilityKind
    public let evidence: String

    public init(kind: RuntimeInstabilityKind, evidence: String) {
        self.kind = kind
        self.evidence = evidence
    }
}

public struct ExecutionTrace: Equatable {
    public let events: [String]
    public let digest: String

    public init(events: [String]) {
        self.events = events
        self.digest = StableDigest.compute(events.joined(separator: "|"))
    }
}

public struct RuntimeReport: Equatable {
    public let status: RuntimeStatus
    public let instabilities: [RuntimeInstability]
    public let trace: ExecutionTrace
}

public struct VerifiedGraph: Equatable {
    public struct Node: Equatable {
        public let id: String
        public let backend: String
        public let differentiable: Bool

        public init(id: String, backend: String, differentiable: Bool) {
            self.id = id
            self.backend = backend
            self.differentiable = differentiable
        }
    }

    public struct ExternalCapability: Equatable {
        public let name: String
        public let interface: String
        public let resource: String
        public let access: String
        public let admissible: Bool
        public let evidence: String

        public init(
            name: String,
            interface: String,
            resource: String,
            access: String,
            admissible: Bool,
            evidence: String
        ) {
            self.name = name
            self.interface = interface
            self.resource = resource
            self.access = access
            self.admissible = admissible
            self.evidence = evidence
        }
    }

    public let world: String
    public let nodes: [Node]
    public let externalCapabilities: [ExternalCapability]
    public let requiresPrivateANE: Bool
    public let invariantDigest: String

    public init(
        world: String,
        nodes: [Node],
        externalCapabilities: [ExternalCapability] = [],
        requiresPrivateANE: Bool,
        invariantDigest: String
    ) {
        self.world = world
        self.nodes = nodes
        self.externalCapabilities = externalCapabilities
        self.requiresPrivateANE = requiresPrivateANE
        self.invariantDigest = invariantDigest
    }

    public static func example(requiresPrivateANE: Bool) -> VerifiedGraph {
        VerifiedGraph(
            world: "CapabilityStore",
            nodes: [
                Node(id: "put", backend: "metal", differentiable: true),
                Node(id: "secure_eval", backend: "private-ane", differentiable: false),
            ],
            externalCapabilities: [],
            requiresPrivateANE: requiresPrivateANE,
            invariantDigest: "auth_preserved=1.0"
        )
    }

    public static func load(bundlePath: String) throws -> VerifiedGraph {
        let bundleURL = URL(fileURLWithPath: bundlePath)
        let manifest = try BundleManifest.load(bundleURL: bundleURL)
        try manifest.verifyArtifacts(bundleURL: bundleURL)

        let graphURL = bundleURL.appendingPathComponent("graph.json")
        let data = try Data(contentsOf: graphURL)
        let object = try JSONSerialization.jsonObject(with: data)
        guard
            let manifest = object as? [String: Any],
            let world = manifest["world"] as? String,
            let nodeRows = manifest["nodes"] as? [[String: Any]],
            let requiresPrivateANE = manifest["requires_private_ane"] as? Bool
        else {
            throw RuntimeLoadError.malformedManifest(graphURL.path)
        }
        let nodes = try nodeRows.map { row in
            guard
                let id = row["id"] as? String,
                let backend = row["backend"] as? String,
                let differentiable = row["differentiable"] as? Bool
            else {
                throw RuntimeLoadError.malformedManifest(graphURL.path)
            }
            return Node(id: id, backend: backend, differentiable: differentiable)
        }
        let externalRows = manifest["external_capabilities"] as? [[String: Any]] ?? []
        let externalCapabilities = try externalRows.map { row in
            guard
                let name = row["name"] as? String,
                let interface = row["interface"] as? String,
                let resource = row["resource"] as? String,
                let access = row["access"] as? String,
                let admissible = row["admissible"] as? Bool,
                let evidence = row["evidence"] as? String
            else {
                throw RuntimeLoadError.malformedManifest(graphURL.path)
            }
            return ExternalCapability(
                name: name,
                interface: interface,
                resource: resource,
                access: access,
                admissible: admissible,
                evidence: evidence
            )
        }
        return VerifiedGraph(
            world: world,
            nodes: nodes,
            externalCapabilities: externalCapabilities,
            requiresPrivateANE: requiresPrivateANE,
            invariantDigest: "bundle:\(bundlePath)"
        )
    }
}

public enum RuntimeLoadError: Error, Equatable {
    case missingManifest(String)
    case missingArtifact(String)
    case malformedManifest(String)
    case checksumMismatch(String)
    case cryptoUnavailable
}

public final class RuntimeGraph {
    private let graph: VerifiedGraph
    private let ane: PrivateANEBackend
    private let metal: MetalBackend

    public init(graph: VerifiedGraph, ane: PrivateANEBackend, metal: MetalBackend = MetalBackend()) {
        self.graph = graph
        self.ane = ane
        self.metal = metal
    }

    public func realize() -> RuntimeReport {
        var events = ["world:\(graph.world)", "invariants:\(graph.invariantDigest)"]
        events.append(contentsOf: graph.nodes.map { "node:\($0.id):\($0.backend)" })
        events.append(contentsOf: graph.externalCapabilities.map {
            "external:\($0.name):\($0.interface):\($0.resource):\($0.access)"
        })

        if let rejected = graph.externalCapabilities.first(where: { !$0.admissible || $0.evidence.isEmpty }) {
            return RuntimeReport(
                status: .isolated,
                instabilities: [
                    RuntimeInstability(
                        kind: .externalInadmissible,
                        evidence: "external capability \(rejected.name) lacks admissible evidence"
                    )
                ],
                trace: ExecutionTrace(events: events)
            )
        }

        if graph.nodes.contains(where: { $0.backend == "metal" }) {
            let metalStatus = metal.probeSharedBuffer(byteCount: 4096)
            events.append("metal:\(metalStatus.trace)")
            if !metalStatus.available {
                return RuntimeReport(
                    status: .isolated,
                    instabilities: [
                        RuntimeInstability(kind: .backendInadmissible, evidence: metalStatus.evidence)
                    ],
                    trace: ExecutionTrace(events: events)
                )
            }
        }

        if graph.requiresPrivateANE {
            let availability = ane.load()
            events.append("ane:\(availability.trace)")
            if !availability.available {
                return RuntimeReport(
                    status: .isolated,
                    instabilities: [
                        RuntimeInstability(
                            kind: .backendInadmissible,
                            evidence: availability.evidence
                        )
                    ],
                    trace: ExecutionTrace(events: events)
                )
            }
        }

        events.append("realized")
        return RuntimeReport(status: .realized, instabilities: [], trace: ExecutionTrace(events: events))
    }

    public func replay(_ trace: ExecutionTrace) -> RuntimeReport {
        if let rejected = graph.externalCapabilities.first(where: { !$0.admissible || $0.evidence.isEmpty }) {
            return RuntimeReport(
                status: .isolated,
                instabilities: [
                    RuntimeInstability(
                        kind: .externalInadmissible,
                        evidence: "external capability \(rejected.name) lacks admissible evidence"
                    )
                ],
                trace: ExecutionTrace(events: trace.events)
            )
        }
        if graph.requiresPrivateANE {
            return realize()
        }
        return RuntimeReport(status: .realized, instabilities: [], trace: ExecutionTrace(events: trace.events))
    }
}

public final class MetalBackend {
    private let forceUnavailable: Bool

    public init(forceUnavailable: Bool = false) {
        self.forceUnavailable = forceUnavailable
    }

    public func probeSharedBuffer(byteCount: Int) -> (available: Bool, evidence: String, trace: String) {
        if forceUnavailable {
            return (false, "Metal unavailable by test override", "forced-unavailable")
        }

        #if canImport(Metal)
        guard let device = MTLCreateSystemDefaultDevice() else {
            return (false, "Metal system device is unavailable", "no-device")
        }
        guard device.makeBuffer(length: byteCount, options: [.storageModeShared]) != nil else {
            return (false, "Metal shared buffer allocation failed", "shared-buffer-failed")
        }
        return (true, "Metal shared buffer available on \(device.name)", "shared-buffer-ok")
        #else
        return (false, "Metal framework is unavailable in this Swift toolchain", "metal-unavailable")
        #endif
    }
}

public final class PrivateANEBackend {
    private let forceUnavailable: Bool

    public init(forceUnavailable: Bool = false) {
        self.forceUnavailable = forceUnavailable
    }

    public func load() -> (available: Bool, evidence: String, trace: String) {
        if forceUnavailable {
            return (
                false,
                "private _ANEClient/_ANECompiler symbols unavailable by test override",
                "forced-unavailable"
            )
        }

        let compiler = dlopen("/System/Library/PrivateFrameworks/ANECompiler.framework/ANECompiler", RTLD_NOW)
        let client = dlopen("/System/Library/PrivateFrameworks/AppleNeuralEngine.framework/AppleNeuralEngine", RTLD_NOW)
        defer {
            if compiler != nil { dlclose(compiler) }
            if client != nil { dlclose(client) }
        }

        guard compiler != nil, client != nil else {
            return (
                false,
                "private _ANEClient/_ANECompiler frameworks could not be loaded",
                "dlopen-failed"
            )
        }
        return (true, "private ANE frameworks loaded", "dlopen-ok")
    }
}

enum StableDigest {
    static func compute(_ value: String) -> String {
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in value.utf8 {
            hash ^= UInt64(byte)
            hash &*= 0x100000001b3
        }
        return String(format: "%016llx", hash)
    }
}

private struct BundleManifest {
    let artifactChecksums: [String: String]

    static func load(bundleURL: URL) throws -> BundleManifest {
        let manifestURL = bundleURL.appendingPathComponent("manifest.json")
        guard FileManager.default.fileExists(atPath: manifestURL.path) else {
            throw RuntimeLoadError.missingManifest(manifestURL.path)
        }
        let data = try Data(contentsOf: manifestURL)
        let object = try JSONSerialization.jsonObject(with: data)
        guard
            let manifest = object as? [String: Any],
            let schemaVersion = manifest["schema_version"] as? Int,
            schemaVersion >= minimumBundleManifestSchemaVersion,
            schemaVersion <= currentBundleManifestSchemaVersion,
            let checksums = manifest["artifact_checksums"] as? [String: String]
        else {
            throw RuntimeLoadError.malformedManifest(manifestURL.path)
        }
        return BundleManifest(artifactChecksums: checksums)
    }

    func verifyArtifacts(bundleURL: URL) throws {
        for (file, expected) in artifactChecksums {
            let artifactURL = bundleURL.appendingPathComponent(file)
            guard FileManager.default.fileExists(atPath: artifactURL.path) else {
                throw RuntimeLoadError.missingArtifact(file)
            }
            let actual = try Self.sha256URI(Data(contentsOf: artifactURL))
            if actual != expected {
                throw RuntimeLoadError.checksumMismatch(file)
            }
        }
    }

    private static func sha256URI(_ data: Data) throws -> String {
        #if canImport(CryptoKit)
        let digest = SHA256.hash(data: data)
        return "sha256:" + digest.map { String(format: "%02x", $0) }.joined()
        #else
        throw RuntimeLoadError.cryptoUnavailable
        #endif
    }
}
