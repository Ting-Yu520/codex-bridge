import Foundation
import MCP
import XCTest
@testable import BridgeMCP

final class MCPModernResponseCachingTests: XCTestCase {
  func testModernResourceReadAddsRequiredFieldsAndPreservesJSONRPCResult() async throws {
    let originalResult = ReadResource.Result(
      contents: [
        .text(
          "resource body",
          uri: "file:///project/README.md",
          mimeType: "text/markdown",
          _meta: Metadata(additionalFields: ["contentMarker": .string("keep")])
        )
      ],
      _meta: Metadata(additionalFields: ["resultMarker": .string("keep")])
    )
    let sdkResultData = try JSONEncoder().encode(originalResult)
    let sdkResult = try XCTUnwrap(
      JSONSerialization.jsonObject(with: sdkResultData) as? [String: Any]
    )
    XCTAssertNil(sdkResult["ttlMs"])
    XCTAssertNil(sdkResult["cacheScope"])
    XCTAssertNil(sdkResult["resultType"])

    let requestID = 17
    let responseData = try JSONSerialization.data(withJSONObject: [
      "jsonrpc": "2.0",
      "id": requestID,
      "result": sdkResult,
    ])
    let registry = MCPSessionRegistry(
      boundPort: 1,
      serverFactory: { _ in fatalError("The response normalizer does not start a server") }
    )

    let normalized = await registry.addingModernServerInfo(
      to: .data(responseData, headers: ["Content-Type": "application/json"]),
      method: "resources/read"
    )
    guard case .data(let normalizedData, let headers) = normalized else {
      return XCTFail("Expected a JSON-RPC response body")
    }

    let response = try XCTUnwrap(
      JSONSerialization.jsonObject(with: normalizedData) as? [String: Any]
    )
    XCTAssertEqual(response["jsonrpc"] as? String, "2.0")
    XCTAssertEqual(response["id"] as? Int, requestID)

    let result = try XCTUnwrap(response["result"] as? [String: Any])
    XCTAssertEqual(result["resultType"] as? String, "complete")
    XCTAssertEqual(result["ttlMs"] as? Int, 0)
    XCTAssertEqual(result["cacheScope"] as? String, "private")

    let contents = try XCTUnwrap(result["contents"] as? [[String: Any]])
    XCTAssertEqual(contents.first?["uri"] as? String, "file:///project/README.md")
    XCTAssertEqual(contents.first?["text"] as? String, "resource body")
    XCTAssertEqual(
      (contents.first?["_meta"] as? [String: Any])?["contentMarker"] as? String,
      "keep"
    )

    let metadata = try XCTUnwrap(result["_meta"] as? [String: Any])
    XCTAssertEqual(metadata["resultMarker"] as? String, "keep")
    XCTAssertNotNil(metadata["io.modelcontextprotocol/serverInfo"])
    XCTAssertEqual(headers["Content-Type"], "application/json")
  }

  func testAllModernCacheableOperationsReceiveRequiredHints() {
    let methods = [
      "server/discover",
      "tools/list",
      "prompts/list",
      "resources/list",
      "resources/templates/list",
      "resources/read",
    ]

    for method in methods {
      let result = MCPModernResponseMetadata.addingRequiredFields(
        to: ["resultType": "complete"],
        method: method
      )
      XCTAssertEqual(result["resultType"] as? String, "complete", method)
      XCTAssertEqual(result["ttlMs"] as? Int, 0, method)
      XCTAssertEqual(result["cacheScope"] as? String, "private", method)
    }
  }

  func testModernToolsListAddsRequiredFieldsAndPreservesDiscoveryEnvelope() async throws {
    let sdkResultData = try JSONEncoder().encode(ListTools.Result(tools: []))
    let sdkResult = try XCTUnwrap(
      JSONSerialization.jsonObject(with: sdkResultData) as? [String: Any]
    )
    let responseData = try JSONSerialization.data(withJSONObject: [
      "jsonrpc": "2.0",
      "id": "tools-1",
      "result": sdkResult,
    ])
    let registry = MCPSessionRegistry(
      boundPort: 1,
      serverFactory: { _ in fatalError("The response normalizer does not start a server") }
    )

    let normalized = await registry.addingModernServerInfo(
      to: .data(responseData),
      method: "tools/list"
    )
    guard case .data(let normalizedData, _) = normalized else {
      return XCTFail("Expected a JSON-RPC response body")
    }

    let response = try XCTUnwrap(
      JSONSerialization.jsonObject(with: normalizedData) as? [String: Any]
    )
    XCTAssertEqual(response["jsonrpc"] as? String, "2.0")
    XCTAssertEqual(response["id"] as? String, "tools-1")
    let result = try XCTUnwrap(response["result"] as? [String: Any])
    XCTAssertEqual(result["resultType"] as? String, "complete")
    XCTAssertEqual(result["ttlMs"] as? Int, 0)
    XCTAssertEqual(result["cacheScope"] as? String, "private")
    XCTAssertEqual((result["tools"] as? [Any])?.count, 0)
  }

  func testExistingCacheHintsAndInputRequiredResultsArePreserved() {
    let completeResult = MCPModernResponseMetadata.addingRequiredFields(
      to: ["resultType": "complete", "ttlMs": 1200, "cacheScope": "public"],
      method: "resources/read"
    )
    XCTAssertEqual(completeResult["ttlMs"] as? Int, 1200)
    XCTAssertEqual(completeResult["cacheScope"] as? String, "public")

    let inputRequiredResult = MCPModernResponseMetadata.addingRequiredFields(
      to: ["resultType": "input_required", "requestState": "opaque"],
      method: "resources/read"
    )
    XCTAssertEqual(inputRequiredResult["resultType"] as? String, "input_required")
    XCTAssertNil(inputRequiredResult["ttlMs"])
    XCTAssertNil(inputRequiredResult["cacheScope"])
  }

  func testNonCacheableModernResultsOnlyReceiveTheModernDiscriminator() {
    let result = MCPModernResponseMetadata.addingRequiredFields(
      to: ["content": []],
      method: "tools/call"
    )
    XCTAssertEqual(result["resultType"] as? String, "complete")
    XCTAssertNil(result["ttlMs"])
    XCTAssertNil(result["cacheScope"])
  }
}
