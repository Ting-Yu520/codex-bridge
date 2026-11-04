import Foundation
import MCP
import XCTest
@testable import BridgeMCP

private let syntheticResourceURI = "file:///synthetic/mcp-cache-hints.txt"
private let modernProtocolVersion = "2026-07-28"

private enum FixtureServerMode: Sendable {
  case standard
  case explicitCache
  case inputRequired
  case jsonRPCError
}

private enum RouteTestFailure: Error {
  case missingCaptureDirectory
  case captureDirectoryOutsideRunnerTemp
  case unexpectedHTTPStatus
  case missingResponseBody
  case invalidResponseBody
  case unexpectedResponseTransport
  case missingSSEJSONRPCMessage
}

private enum ExplicitCacheRead: Method {
  static let name = "resources/read"
  typealias Parameters = ReadResource.Parameters

  struct Result: Codable, Hashable, Sendable {
    let resultType: String
    let contents: [Resource.Content]
    let ttlMs: Int
    let cacheScope: String

    init(contents: [Resource.Content]) {
      resultType = "complete"
      self.contents = contents
      ttlMs = 4_500
      cacheScope = "public"
    }
  }
}

private enum InputRequiredRead: Method {
  static let name = "resources/read"
  typealias Parameters = ReadResource.Parameters

  struct Result: Codable, Hashable, Sendable {
    let resultType = "input_required"
  }
}

private func makeFixtureServer(_ mode: FixtureServerMode) async -> Server {
  let server = Server(
    name: "synthetic-mcp-route-test",
    version: "1.0.0",
    capabilities: .init(
      prompts: .init(listChanged: false),
      resources: .init(listChanged: false),
      tools: .init(listChanged: false)
    )
  )
  await server.withMethodHandler(ListTools.self) { _ in ListTools.Result(tools: []) }
  await server.withMethodHandler(ListPrompts.self) { _ in ListPrompts.Result(prompts: []) }
  await server.withMethodHandler(ListResourceTemplates.self) { _ in
    ListResourceTemplates.Result(templates: [])
  }
  await server.withMethodHandler(ListResources.self) { _ in
    ListResources.Result(resources: [
      Resource(name: "synthetic-resource", uri: syntheticResourceURI, mimeType: "text/plain")
    ])
  }

  let content: Resource.Content = .text(
    "synthetic resource body",
    uri: syntheticResourceURI,
    mimeType: "text/plain",
    _meta: Metadata(additionalFields: ["contentMarker": .string("keep")])
  )
  switch mode {
  case .standard:
    await server.withMethodHandler(ReadResource.self) { _ in
      ReadResource.Result(
        contents: [content],
        _meta: Metadata(additionalFields: ["resultMarker": .string("keep")])
      )
    }
  case .explicitCache:
    await server.withMethodHandler(ExplicitCacheRead.self) { _ in
      ExplicitCacheRead.Result(contents: [content])
    }
  case .inputRequired:
    await server.withMethodHandler(InputRequiredRead.self) { _ in InputRequiredRead.Result() }
  case .jsonRPCError:
    await server.withMethodHandler(ReadResource.self) { _ -> ReadResource.Result in
      throw MCPError.invalidParams("Synthetic invalid resource URI")
    }
  }
  return server
}

final class MCPModernResponseRouteTests: XCTestCase, @unchecked Sendable {
  private let boundPort = 43123

  func testDiscoverToolsListAndResourcesListUseActualModernRoutes() async throws {
    let registry = makeRegistry()
    defer { Task { await registry.stop() } }

    for (method, id, captureName) in [
      ("server/discover", 101, "server-discover"),
      ("tools/list", 102, "tools-list"),
      ("resources/list", 103, "resources-list"),
      ("prompts/list", 104, "prompts-list"),
      ("resources/templates/list", 105, "resources-templates-list"),
    ] {
      let request = try modernRequest(method: method, id: id)
      let (_, response) = try await routeBody(
        await registry.handle(request), captureName: captureName
      )
      assertComplete(response, id: id)
      let result = try XCTUnwrap(response["result"] as? [String: Any])
      if method == "server/discover" {
        XCTAssertEqual(result["supportedVersions"] as? [String], ["2026-07-28", "2025-11-25"])
      } else if method == "tools/list" {
        XCTAssertEqual((result["tools"] as? [Any])?.count, 0)
      } else if method == "prompts/list" {
        XCTAssertEqual((result["prompts"] as? [Any])?.count, 0)
      } else if method == "resources/templates/list" {
        XCTAssertEqual((result["resourceTemplates"] as? [Any])?.count, 0)
      } else if method == "resources/list" {
        let resources = try XCTUnwrap(result["resources"] as? [[String: Any]])
        XCTAssertEqual(resources.first?["uri"] as? String, syntheticResourceURI)
      }
    }
  }

  func testResourcesReadActualSDKRoutePreservesContentsMetadataAndDefaults() async throws {
    let registry = makeRegistry()
    defer { Task { await registry.stop() } }
    let request = try modernRequest(
      method: "resources/read", id: 104,
      params: ["uri": syntheticResourceURI], routedName: syntheticResourceURI
    )
    let (_, response) = try await routeBody(
      await registry.handle(request), captureName: "resources-read-default"
    )
    assertComplete(response, id: 104)
    let result = try XCTUnwrap(response["result"] as? [String: Any])
    let contents = try XCTUnwrap(result["contents"] as? [[String: Any]])
    XCTAssertEqual(contents.first?["uri"] as? String, syntheticResourceURI)
    XCTAssertEqual(contents.first?["text"] as? String, "synthetic resource body")
    XCTAssertEqual((contents.first?["_meta"] as? [String: Any])?["contentMarker"] as? String, "keep")
    let metadata = try XCTUnwrap(result["_meta"] as? [String: Any])
    XCTAssertEqual(metadata["resultMarker"] as? String, "keep")
    XCTAssertNotNil(metadata["io.modelcontextprotocol/serverInfo"])
  }

  func testResourcesReadPreservesExplicitCacheValuesFromSDKRoute() async throws {
    let registry = makeRegistry(mode: .explicitCache)
    defer { Task { await registry.stop() } }
    let request = try modernRequest(
      method: "resources/read", id: 105,
      params: ["uri": syntheticResourceURI], routedName: syntheticResourceURI
    )
    let (_, response) = try await routeBody(
      await registry.handle(request), captureName: "resources-read-explicit-cache"
    )
    let result = try XCTUnwrap(response["result"] as? [String: Any])
    XCTAssertEqual(response["jsonrpc"] as? String, "2.0")
    XCTAssertEqual(response["id"] as? Int, 105)
    XCTAssertEqual(result["resultType"] as? String, "complete")
    XCTAssertEqual(result["ttlMs"] as? Int, 4_500)
    XCTAssertEqual(result["cacheScope"] as? String, "public")
    XCTAssertNotNil(result["contents"])
  }

  func testInputRequiredActualSDKRouteDoesNotReceiveCacheHints() async throws {
    let registry = makeRegistry(mode: .inputRequired)
    defer { Task { await registry.stop() } }
    let request = try modernRequest(
      method: "resources/read", id: 106,
      params: ["uri": syntheticResourceURI], routedName: syntheticResourceURI
    )
    let (_, response) = try await routeBody(
      await registry.handle(request), captureName: "resources-read-input-required"
    )
    let result = try XCTUnwrap(response["result"] as? [String: Any])
    XCTAssertEqual(response["jsonrpc"] as? String, "2.0")
    XCTAssertEqual(response["id"] as? Int, 106)
    XCTAssertEqual(result["resultType"] as? String, "input_required")
    XCTAssertNil(result["ttlMs"])
    XCTAssertNil(result["cacheScope"])
  }

  func testJSONRPCErrorFromActualSDKRouteRemainsAnErrorResponse() async throws {
    let registry = makeRegistry(mode: .jsonRPCError)
    defer { Task { await registry.stop() } }
    let request = try modernRequest(
      method: "resources/read", id: 107,
      params: ["uri": syntheticResourceURI], routedName: syntheticResourceURI
    )
    let (_, response) = try await routeBody(
      await registry.handle(request), captureName: "resources-read-jsonrpc-error"
    )
    XCTAssertEqual(response["jsonrpc"] as? String, "2.0")
    XCTAssertEqual(response["id"] as? Int, 107)
    XCTAssertNil(response["result"])
    let error = try XCTUnwrap(response["error"] as? [String: Any])
    XCTAssertEqual(error["code"] as? Int, -32_602)
    XCTAssertEqual(error["message"] as? String, "Invalid params: Synthetic invalid resource URI")
    let errorData = try XCTUnwrap(error["data"] as? [String: Any])
    XCTAssertEqual(errorData["detail"] as? String, "Synthetic invalid resource URI")
  }

  func testLegacySessionToolsListUsesOriginalSSEPathWithoutModernHints() async throws {
    let registry = makeRegistry()
    defer { Task { await registry.stop() } }

    let initialize = try jsonData([
      "jsonrpc": "2.0", "id": 201, "method": "initialize",
      "params": [
        "protocolVersion": "2025-11-25",
        "capabilities": [:] as [String: Any],
        "clientInfo": ["name": "synthetic-legacy-test", "version": "1"],
      ] as [String: Any],
    ])
    let initializeResponse = await registry.handle(
      HTTPRequest(method: "POST", headers: legacyHeaders(), body: initialize, path: "/mcp")
    )
    let initializeObject = try jsonObject(await jsonRPCData(from: initializeResponse))
    XCTAssertEqual(initializeResponse.statusCode, 200)
    XCTAssertEqual(initializeObject["id"] as? Int, 201)

    let sessionID = try XCTUnwrap(initializeResponse.headers[HTTPHeaderName.sessionID])
    let initializedBody = try jsonData(["jsonrpc": "2.0", "method": "notifications/initialized"])
    let initializedResponse = await registry.handle(HTTPRequest(
      method: "POST", headers: legacyHeaders(sessionID: sessionID),
      body: initializedBody, path: "/mcp"
    ))
    XCTAssertEqual(initializedResponse.statusCode, 202)

    let toolsBody = try jsonData([
      "jsonrpc": "2.0", "id": 202, "method": "tools/list", "params": [:] as [String: Any],
    ])
    let toolsResponse = await registry.handle(HTTPRequest(
      method: "POST", headers: legacyHeaders(sessionID: sessionID),
      body: toolsBody, path: "/mcp"
    ))
    XCTAssertEqual(toolsResponse.statusCode, 200)
    guard case .stream(_, _) = toolsResponse else {
      XCTFail("Legacy tools/list did not remain on the stateful SSE transport")
      return
    }
    let response = try jsonObject(await jsonRPCData(from: toolsResponse))
    let result = try XCTUnwrap(response["result"] as? [String: Any])
    XCTAssertEqual(response["jsonrpc"] as? String, "2.0")
    XCTAssertEqual(response["id"] as? Int, 202)
    XCTAssertNil(result["resultType"])
    XCTAssertNil(result["ttlMs"])
    XCTAssertNil(result["cacheScope"])
  }

  private func makeRegistry(mode: FixtureServerMode = .standard) -> MCPSessionRegistry {
    MCPSessionRegistry(
      boundPort: boundPort,
      serverFactory: { _ in await makeFixtureServer(mode) },
      statelessServerFactory: { await makeFixtureServer(mode) },
      discoveryInstructionsProvider: { _ in "Synthetic MCP route test only." }
    )
  }

  private func modernRequest(
    method: String, id: Int, params: [String: Any] = [:], routedName: String? = nil
  ) throws -> HTTPRequest {
    var requestParams = params
    requestParams["_meta"] = [
      "io.modelcontextprotocol/protocolVersion": modernProtocolVersion,
      "io.modelcontextprotocol/clientCapabilities": [:] as [String: Any],
    ]
    let body = try jsonData([
      "jsonrpc": "2.0", "id": id, "method": method, "params": requestParams,
    ])
    var headers = [
      "Host": "127.0.0.1:\(boundPort)",
      "Origin": "http://127.0.0.1:\(boundPort)",
      "Accept": "application/json, text/event-stream",
      "Content-Type": "application/json",
      "Mcp-Protocol-Version": modernProtocolVersion,
      "Mcp-Method": method,
    ]
    if let routedName { headers["Mcp-Name"] = routedName }
    return HTTPRequest(method: "POST", headers: headers, body: body, path: "/mcp")
  }

  private func legacyHeaders(sessionID: String? = nil) -> [String: String] {
    var headers = [
      "Host": "127.0.0.1:\(boundPort)",
      "Origin": "http://127.0.0.1:\(boundPort)",
      "Accept": "application/json, text/event-stream",
      "Content-Type": "application/json",
      HTTPHeaderName.protocolVersion: "2025-11-25",
    ]
    if let sessionID { headers[HTTPHeaderName.sessionID] = sessionID }
    return headers
  }

  private func routeBody(
    _ response: HTTPResponse, captureName: String
  ) async throws -> (Data, [String: Any]) {
    guard response.statusCode == 200 else {
      XCTFail("Modern route returned a non-success HTTP status [\(captureName)]")
      throw RouteTestFailure.unexpectedHTTPStatus
    }
    guard let data = response.bodyData else {
      XCTFail("Modern route returned no HTTPResponse.bodyData [\(captureName)]")
      throw RouteTestFailure.missingResponseBody
    }
    try capture(data, name: captureName)
    return (data, try jsonObject(data))
  }

  private func capture(_ data: Data, name: String) throws {
    guard let capturePath = ProcessInfo.processInfo.environment["CODEX_BRIDGE_MCP_CAPTURE_DIR"],
      let runnerTempPath = ProcessInfo.processInfo.environment["RUNNER_TEMP"]
    else { throw RouteTestFailure.missingCaptureDirectory }
    let captureDirectory = URL(fileURLWithPath: capturePath, isDirectory: true).standardizedFileURL
    let runnerTempDirectory = URL(fileURLWithPath: runnerTempPath, isDirectory: true).standardizedFileURL
    let captureParent = captureDirectory.deletingLastPathComponent().path
    guard captureParent.caseInsensitiveCompare(runnerTempDirectory.path) == .orderedSame else {
      throw RouteTestFailure.captureDirectoryOutsideRunnerTemp
    }
    try FileManager.default.createDirectory(at: captureDirectory, withIntermediateDirectories: true)
    try data.write(
      to: captureDirectory.appendingPathComponent(name).appendingPathExtension("json"),
      options: .atomic
    )
  }

  private func assertComplete(
    _ response: [String: Any], id: Int, file: StaticString = #filePath, line: UInt = #line
  ) {
    XCTAssertEqual(response["jsonrpc"] as? String, "2.0", file: file, line: line)
    XCTAssertEqual(response["id"] as? Int, id, file: file, line: line)
    guard let result = response["result"] as? [String: Any] else {
      XCTFail("Expected a JSON-RPC result object", file: file, line: line)
      return
    }
    XCTAssertEqual(result["resultType"] as? String, "complete", file: file, line: line)
    XCTAssertEqual(result["ttlMs"] as? Int, 0, file: file, line: line)
    XCTAssertEqual(result["cacheScope"] as? String, "private", file: file, line: line)
  }
}

private func jsonData(_ object: [String: Any]) throws -> Data {
  try JSONSerialization.data(withJSONObject: object)
}

private func jsonObject(_ data: Data) throws -> [String: Any] {
  guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    throw RouteTestFailure.invalidResponseBody
  }
  return value
}

private func jsonRPCData(from response: HTTPResponse) async throws -> Data {
  guard response.statusCode == 200 else { throw RouteTestFailure.unexpectedHTTPStatus }
  switch response {
  case .data(let data, _):
    return data
  case .stream(let stream, _):
    for try await chunk in stream {
      let text = String(decoding: chunk, as: UTF8.self)
      for line in text.components(separatedBy: "\n") where line.hasPrefix("data: ") {
        let value = String(line.dropFirst("data: ".count))
        guard !value.isEmpty, let payload = value.data(using: .utf8) else { continue }
        if let message = try? jsonObject(payload), message["id"] != nil { return payload }
      }
    }
    throw RouteTestFailure.missingSSEJSONRPCMessage
  case .accepted, .ok, .error:
    throw RouteTestFailure.unexpectedResponseTransport
  }
}
