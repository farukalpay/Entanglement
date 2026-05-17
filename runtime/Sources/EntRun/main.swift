import Foundation
import RuntimeKit

let args = Array(CommandLine.arguments.dropFirst())
let graph: VerifiedGraph
let bundlePath = args.first(where: { !$0.hasPrefix("--") })
if let bundle = bundlePath {
    graph = try VerifiedGraph.load(bundlePath: bundle)
} else {
    graph = VerifiedGraph.example(requiresPrivateANE: args.contains("--ane-private"))
}

let runtime = RuntimeGraph(graph: graph, ane: PrivateANEBackend())
let report = runtime.realize()

switch report.status {
case .realized:
    print("REALIZED \(report.trace.digest)")
case .isolated:
    print("ISOLATED \(report.instabilities.map(\.evidence).joined(separator: "; "))")
case .collapsed:
    print("COLLAPSED")
}
