import BridgeLegacyImport
import BridgeMCP
import Foundation
import XCTest
@testable import BridgeIPC

#if os(Windows)
  import FoundationNetworking
  import WinSDK

  private enum MCPProcessHarnessError: Error {
    case missingEnvironment(String)
    case unsafeRunnerEnvironment
    case artifactIdentityMismatch
    case legacyConfigurationPresent
    case dataRootNotIsolated
    case existingIPCServer
    case processExitedBeforeIPCReady
    case ipcReadinessTimeout
    case invalidLocalEndpoint
    case invalidCaptureDirectory
    case requestFailed
    case malformedResponse
    case responseMismatch
  }

  private struct MCPProcessRoute {
    let name: String
    let method: String
    let id: Int
    let params: [String: Any]
    let routedName: String?
    let expected: ExpectedResponse

    enum ExpectedResponse {
      case complete
      case resourceRead(uri: String)
      case jsonRPCError
    }
  }

  final class MCPWindowsExecutableProcessTests: XCTestCase, @unchecked Sendable {
    private let expectedCommit = "f2235028773e7d9e0da714218a5694c4eb8bfef3"
    private let expectedServiceSHA256 =
      "428b39d31c1e57adc0609720d450fa7bd3c56295289a1f46b1863dab69a72521"
    private let validResourceURI = "ui://codex-bridge/file-transfer.html"
    private let invalidResourceURI = "file:///codex-bridge-b1-synthetic-not-present.txt"
    private let protocolVersion = "2026-07-28"

    func testWindowsPortableExecutableServesModernMCPRoutes() async throws {
      #if arch(x86_64)
        do {
          let environment = ProcessInfo.processInfo.environment
          let runnerTemp = try requiredPath("RUNNER_TEMP", in: environment)
          let candidateDirectory = try requiredPath(
            "CODEX_BRIDGE_CANDIDATE_DIR", in: environment)
          let captureDirectory = try requiredPath(
            "CODEX_BRIDGE_MCP_PROCESS_CAPTURE_DIR", in: environment)
          let pidRecordPath = try requiredPath(
            "CODEX_BRIDGE_MCP_PROCESS_PID_FILE", in: environment)
          guard environment["CODEX_BRIDGE_ARTIFACT_VERIFICATION"] == "PASS" else {
            throw MCPProcessHarnessError.artifactIdentityMismatch
          }
          guard environment["CODEX_BRIDGE_CANDIDATE_SHA256"] == expectedServiceSHA256 else {
            throw MCPProcessHarnessError.artifactIdentityMismatch
          }

          let runnerTempURL = URL(fileURLWithPath: runnerTemp, isDirectory: true).standardizedFileURL
          let candidateURL = URL(fileURLWithPath: candidateDirectory, isDirectory: true)
            .standardizedFileURL
          let captureURL = URL(fileURLWithPath: captureDirectory, isDirectory: true).standardizedFileURL
          let pidURL = URL(fileURLWithPath: pidRecordPath).standardizedFileURL
          guard captureURL.deletingLastPathComponent().path.caseInsensitiveCompare(runnerTempURL.path)
              == .orderedSame,
            pidURL.deletingLastPathComponent().path.caseInsensitiveCompare(runnerTempURL.path)
              == .orderedSame
          else {
            throw MCPProcessHarnessError.invalidCaptureDirectory
          }
          guard !FileManager.default.fileExists(atPath: captureURL.path),
            !FileManager.default.fileExists(atPath: pidURL.path)
          else {
            throw MCPProcessHarnessError.invalidCaptureDirectory
          }

          let serviceURL = candidateURL.appendingPathComponent("codex-bridge-service.exe")
          let buildInfoURL = candidateURL.appendingPathComponent("BUILD-INFO.json")
          guard FileManager.default.fileExists(atPath: serviceURL.path),
            let buildInfoData = try? Data(contentsOf: buildInfoURL),
            let buildInfo = try? JSONSerialization.jsonObject(with: buildInfoData) as? [String: Any],
            buildInfo["gitCommit"] as? String == expectedCommit,
            buildInfo["architecture"] as? String == "x64"
          else {
            throw MCPProcessHarnessError.artifactIdentityMismatch
          }

          let legacyRoot = LegacyConfigurationImporter.defaultSourceRoot()
          guard !FileManager.default.fileExists(atPath: legacyRoot.path) else {
            // Existence only: never enumerate or read an existing user configuration directory.
            throw MCPProcessHarnessError.legacyConfigurationPresent
          }
          let dataRootURL = URL(
            fileURLWithPath: environment["CODEX_BRIDGE_VM_DATA_ROOT"]
              ?? runnerTempURL.appendingPathComponent(
                "codex-bridge-b1-data-\(UUID().uuidString)", isDirectory: true).path,
            isDirectory: true
          ).standardizedFileURL
          let profileRootURL = URL(
            fileURLWithPath: environment["CODEX_BRIDGE_VM_PROFILE_ROOT"]
              ?? runnerTempURL.appendingPathComponent(
                "codex-bridge-b1-profile-\(UUID().uuidString)", isDirectory: true).path,
            isDirectory: true
          ).standardizedFileURL
          let appDataRootURL = profileRootURL.appendingPathComponent("AppData", isDirectory: true)
          let appDataURL = appDataRootURL.appendingPathComponent("Roaming", isDirectory: true)
          let localAppDataURL = appDataRootURL.appendingPathComponent("Local", isDirectory: true)
          let codexHomeURL = profileRootURL.appendingPathComponent(
            "CodexHome", isDirectory: true)
          guard dataRootURL.deletingLastPathComponent().path.caseInsensitiveCompare(runnerTempURL.path)
              == .orderedSame,
            profileRootURL.deletingLastPathComponent().path.caseInsensitiveCompare(runnerTempURL.path)
              == .orderedSame,
            !FileManager.default.fileExists(atPath: dataRootURL.path),
            !FileManager.default.fileExists(atPath: profileRootURL.path)
          else {
            throw MCPProcessHarnessError.dataRootNotIsolated
          }

          let pidRecord: [String: Any] = [
            "pid": 0,
            "launchState": "prepared",
            "dataRoot": dataRootURL.path,
            "profileRoot": profileRootURL.path,
            "image": "verified-portable/codex-bridge-service.exe",
            "imagePath": serviceURL.path,
            "imageSha256": expectedServiceSHA256,
            "sourceRoot": environment["CODEX_BRIDGE_VM_SOURCE_ROOT"]
              ?? runnerTempURL.appendingPathComponent("codex-bridge-vm-source-hosted-legacy").path,
            "candidateRoot": environment["CODEX_BRIDGE_VM_CANDIDATE_ROOT"] ?? candidateURL.path,
            "captureDirectory": captureURL.path,
          ]
          let pidData = try JSONSerialization.data(
            withJSONObject: pidRecord, options: [.sortedKeys])
          try pidData.write(to: pidURL, options: .atomic)
          try FileManager.default.createDirectory(
            at: dataRootURL, withIntermediateDirectories: false)
          try FileManager.default.createDirectory(at: appDataURL, withIntermediateDirectories: true)
          try FileManager.default.createDirectory(at: localAppDataURL, withIntermediateDirectories: true)
          try FileManager.default.createDirectory(
            at: codexHomeURL, withIntermediateDirectories: true)
          try FileManager.default.createDirectory(at: captureURL, withIntermediateDirectories: false)

          let pipeName = WindowsPipeIdentity.pipeName(forExecutableDirectory: candidateURL.path)
          try assertNamedPipeIsAbsent(pipeName)
          let service = Process()
          service.executableURL = serviceURL
          service.arguments = ["--data-root", dataRootURL.path]
          service.currentDirectoryURL = candidateURL
          service.environment = try minimalServiceEnvironment(
            runnerTemp: runnerTempURL.path,
            candidateDirectory: candidateURL.path,
            profileRoot: profileRootURL.path,
            appData: appDataURL.path,
            localAppData: localAppDataURL.path,
            codexHome: codexHomeURL.path,
            inherited: environment
          )
          service.standardOutput = FileHandle.nullDevice
          service.standardError = FileHandle.nullDevice
          var launchIntentRecord = pidRecord
          launchIntentRecord["launchState"] = "launching"
          let launchIntentData = try JSONSerialization.data(
            withJSONObject: launchIntentRecord, options: [.sortedKeys])
          try launchIntentData.write(to: pidURL, options: .atomic)
          print("B1_PROCESS_LAUNCH_INTENT image=verified-portable/codex-bridge-service.exe")
          try service.run()

          var runningRecord = pidRecord
          runningRecord["pid"] = service.processIdentifier
          runningRecord["launchState"] = "started"
          runningRecord["imagePath"] = serviceURL.path
          runningRecord["imageSha256"] = expectedServiceSHA256
          let startedAtFormatter = ISO8601DateFormatter()
          startedAtFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
          runningRecord["startedAtUtc"] = startedAtFormatter.string(from: Date())
          runningRecord["testRunnerPid"] = Int(GetCurrentProcessId())
          let runningData = try JSONSerialization.data(
            withJSONObject: runningRecord, options: [.sortedKeys])
          try runningData.write(to: pidURL, options: .atomic)
          print(
            "B1_PROCESS_START status=started pid=\(service.processIdentifier) image=verified-portable/codex-bridge-service.exe"
          )

          let transport = NamedPipeServiceTransport(pipeName: pipeName)
          let client = BridgeServiceClient(transport: transport)
          do {
            try await waitForIPC(client, process: service)
            print("B1_IPC status=ready transport=installation-scoped-named-pipe")
            try await client.setMCPClientExposureMode(clientID: "qwen.studio", mode: .readOnly)
            try await client.setMCPClientEnabled(clientID: "qwen.studio", enabled: true)
            let connection = try await client.localMCPConnection(clientID: "qwen.studio")
            guard let endpointURL = URL(string: connection.localMCPURL),
              endpointURL.scheme == "http",
              endpointURL.host == "127.0.0.1",
              endpointURL.path == "/mcp",
              endpointURL.port.map({ (1...65_535).contains($0) }) == true,
              !connection.token.isEmpty
            else {
              throw MCPProcessHarnessError.invalidLocalEndpoint
            }
            print("B1_MCP_INIT status=ready transport=loopback-http auth=ephemeral-in-memory")

            let configuration = URLSessionConfiguration.ephemeral
            configuration.connectionProxyDictionary = [:]
            configuration.httpCookieStorage = nil
            configuration.urlCache = nil
            let session = URLSession(configuration: configuration)
            defer { session.invalidateAndCancel() }

            let routes = makeRoutes()
            var passed = 0
            for route in routes {
              do {
                let (httpResponse, rawBody, contentType) = try await send(
                  route,
                  to: endpointURL,
                  token: connection.token,
                  session: session,
                  captureDirectory: captureURL
                )
                try validate(
                  route,
                  httpResponse: httpResponse,
                  body: rawBody,
                  contentType: contentType
                )
                passed += 1
                print(
                  "B1_MCP_ROUTE name=\(route.name) status=PASS http_status=\(httpResponse.statusCode)"
                )
              } catch let error as MCPProcessHarnessError {
                print(
                  "B1_MCP_ROUTE name=\(route.name) status=FAIL error_category=\(category(error))"
                )
                XCTFail("route=\(route.name) error_category=\(category(error))")
              } catch {
                print(
                  "B1_MCP_ROUTE name=\(route.name) status=FAIL error_category=request_or_response"
                )
                XCTFail("route=\(route.name) error_category=request_or_response")
              }
            }
            print("B1_MCP_CAPTURE_SUMMARY expected=5 captured=\(captureCount(at: captureURL))")
            XCTAssertEqual(passed, routes.count, "All actual EXE routes must pass their assertions")
            XCTAssertEqual(
              captureCount(at: captureURL), routes.count,
              "Every route must leave a raw body capture")
            await client.invalidate()
          } catch {
            await client.invalidate()
            throw error
          }
        } catch let error as MCPProcessHarnessError {
          print("B1_PROCESS status=FAIL error_category=\(category(error))")
          throw error
        } catch {
          print("B1_PROCESS status=FAIL error_category=harness_or_launch_error")
          throw error
        }
      #else
        throw XCTSkip("This process-level test requires a Windows x64 runner.")
      #endif
    }

    private func makeRoutes() -> [MCPProcessRoute] {
      [
        MCPProcessRoute(
          name: "server-discover", method: "server/discover", id: 801,
          params: [:], routedName: nil, expected: .complete),
        MCPProcessRoute(
          name: "tools-list", method: "tools/list", id: 802,
          params: [:], routedName: nil, expected: .complete),
        MCPProcessRoute(
          name: "resources-list", method: "resources/list", id: 803,
          params: [:], routedName: nil, expected: .complete),
        MCPProcessRoute(
          name: "resources-read", method: "resources/read", id: 804,
          params: ["uri": validResourceURI], routedName: validResourceURI,
          expected: .resourceRead(uri: validResourceURI)),
        MCPProcessRoute(
          name: "resources-read-invalid", method: "resources/read", id: 805,
          params: ["uri": invalidResourceURI], routedName: invalidResourceURI,
          expected: .jsonRPCError),
      ]
    }

    private func send(
      _ route: MCPProcessRoute,
      to endpoint: URL,
      token: String,
      session: URLSession,
      captureDirectory: URL
    ) async throws -> (HTTPURLResponse, Data, String) {
      var parameters = route.params
      parameters["_meta"] = [
        "io.modelcontextprotocol/protocolVersion": protocolVersion,
        "io.modelcontextprotocol/clientCapabilities": [:] as [String: Any],
      ] as [String: Any]
      let requestBody = try JSONSerialization.data(
        withJSONObject: [
          "jsonrpc": "2.0", "id": route.id, "method": route.method, "params": parameters,
        ],
        options: [.sortedKeys]
      )
      var request = URLRequest(url: endpoint, timeoutInterval: 20)
      request.httpMethod = "POST"
      request.httpBody = requestBody
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
      request.setValue("application/json, text/event-stream", forHTTPHeaderField: "Accept")
      request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
      if let port = endpoint.port {
        request.setValue("http://127.0.0.1:\(port)", forHTTPHeaderField: "Origin")
      }
      request.setValue(protocolVersion, forHTTPHeaderField: "Mcp-Protocol-Version")
      request.setValue(route.method, forHTTPHeaderField: "Mcp-Method")
      request.setValue(token, forHTTPHeaderField: MCPHTTPConfiguration.tunnelAuthenticationHeader)
      if let routedName = route.routedName {
        request.setValue(routedName, forHTTPHeaderField: "Mcp-Name")
      }
      let (body, response) = try await session.data(for: request)
      guard let httpResponse = response as? HTTPURLResponse else {
        throw MCPProcessHarnessError.requestFailed
      }
      let contentType = httpResponse.value(forHTTPHeaderField: "Content-Type") ?? ""
      try capture(body, contentType: contentType, name: route.name, directory: captureDirectory)
      return (httpResponse, body, contentType)
    }

    private func validate(
      _ route: MCPProcessRoute,
      httpResponse: HTTPURLResponse,
      body: Data,
      contentType: String
    ) throws {
      guard httpResponse.statusCode == 200 else { throw MCPProcessHarnessError.requestFailed }
      guard let response = decodeJSONRPC(body, contentType: contentType) else {
        throw MCPProcessHarnessError.malformedResponse
      }
      guard response["jsonrpc"] as? String == "2.0",
        integer(response["id"]) == route.id
      else {
        throw MCPProcessHarnessError.responseMismatch
      }

      switch route.expected {
      case .complete:
        guard let result = response["result"] as? [String: Any], response["error"] == nil,
          result["resultType"] as? String == "complete",
          integer(result["ttlMs"]) == 0,
          result["cacheScope"] as? String == "private"
        else {
          throw MCPProcessHarnessError.responseMismatch
        }
        if route.method == "server/discover" {
          guard let supportedVersions = result["supportedVersions"] as? [String],
            supportedVersions.contains(protocolVersion)
          else { throw MCPProcessHarnessError.responseMismatch }
        } else if route.method == "tools/list" {
          guard result["tools"] is [Any] else { throw MCPProcessHarnessError.responseMismatch }
        } else if route.method == "resources/list" {
          guard let resources = result["resources"] as? [[String: Any]],
            resources.contains(where: { $0["uri"] as? String == validResourceURI })
          else { throw MCPProcessHarnessError.responseMismatch }
        }
      case .resourceRead(let uri):
        guard let result = response["result"] as? [String: Any], response["error"] == nil,
          result["resultType"] as? String == "complete",
          integer(result["ttlMs"]) == 0,
          result["cacheScope"] as? String == "private",
          let contents = result["contents"] as? [[String: Any]],
          let content = contents.first,
          content["uri"] as? String == uri,
          let text = content["text"] as? String,
          !text.isEmpty,
          content["_meta"] as? [String: Any] != nil,
          let metadata = result["_meta"] as? [String: Any],
          metadata["io.modelcontextprotocol/serverInfo"] != nil
        else {
          throw MCPProcessHarnessError.responseMismatch
        }
      case .jsonRPCError:
        guard response["result"] == nil,
          let error = response["error"] as? [String: Any],
          integer(error["code"]) == -32_602,
          error["message"] as? String == "Invalid params: Unknown resource URI.",
          let errorData = error["data"] as? [String: Any],
          errorData["detail"] as? String == "Unknown resource URI."
        else {
          throw MCPProcessHarnessError.responseMismatch
        }
      }
    }

    private func decodeJSONRPC(_ body: Data, contentType: String) -> [String: Any]? {
      if contentType.lowercased().hasPrefix("application/json") {
        return (try? JSONSerialization.jsonObject(with: body)) as? [String: Any]
      }
      guard contentType.lowercased().hasPrefix("text/event-stream"),
        let text = String(data: body, encoding: .utf8)
      else { return nil }
      let payloads = text.components(separatedBy: "\n\n").compactMap { event -> [String: Any]? in
        let lines = event.split(whereSeparator: \.isNewline)
        let dataLines = lines.compactMap { line -> String? in
          guard line.hasPrefix("data:") else { return nil }
          return String(line.dropFirst(5)).trimmingCharacters(in: .whitespaces)
        }
        guard !dataLines.isEmpty,
          let data = dataLines.joined(separator: "\n").data(using: .utf8)
        else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
      }.filter { $0["jsonrpc"] as? String == "2.0" }
      return payloads.count == 1 ? payloads.first : nil
    }

    private func capture(_ body: Data, contentType: String, name: String, directory: URL) throws {
      try body.write(to: directory.appendingPathComponent("\(name).body"), options: .atomic)
      try Data(contentType.utf8).write(
        to: directory.appendingPathComponent("\(name).content-type"), options: .atomic)
    }

    private func captureCount(at directory: URL) -> Int {
      let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
      return names.filter { $0.hasSuffix(".body") }.count
    }

    private func waitForIPC(_ client: BridgeServiceClient, process: Process) async throws {
      for _ in 0..<120 {
        guard process.isRunning else { throw MCPProcessHarnessError.processExitedBeforeIPCReady }
        do {
          _ = try await client.status()
          return
        } catch {
          try await Task.sleep(nanoseconds: 250_000_000)
        }
      }
      throw MCPProcessHarnessError.ipcReadinessTimeout
    }

    private func minimalServiceEnvironment(
      runnerTemp: String,
      candidateDirectory: String,
      profileRoot: String,
      appData: String,
      localAppData: String,
      codexHome: String,
      inherited: [String: String]
    ) throws -> [String: String] {
      var result: [String: String] = [:]
      for name in ["SystemRoot", "WINDIR"] {
        guard let value = inherited[name], !value.isEmpty else {
          throw MCPProcessHarnessError.missingEnvironment(name)
        }
        result[name] = value
      }
      result["USERPROFILE"] = profileRoot
      result["APPDATA"] = appData
      result["LOCALAPPDATA"] = localAppData
      result["CODEX_HOME"] = codexHome
      result["TEMP"] = runnerTemp
      result["TMP"] = runnerTemp
      result["PATH"] = candidateDirectory + ";" + (inherited["SystemRoot"] ?? "") + "\\System32"
      let forbidden = Set([
        "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "CODEX_BRIDGE_RUNTIME_KEY", "OPENAI_API_KEY",
        "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy",
      ])
      guard Set(result.keys).isDisjoint(with: forbidden) else {
        throw MCPProcessHarnessError.unsafeRunnerEnvironment
      }
      return result
    }

    private func requiredPath(_ name: String, in environment: [String: String]) throws -> String {
      guard let value = environment[name], !value.isEmpty else {
        throw MCPProcessHarnessError.missingEnvironment(name)
      }
      return value
    }

    private func integer(_ value: Any?) -> Int? {
      if let value = value as? Int { return value }
      if let number = value as? NSNumber { return number.intValue }
      return nil
    }

    private func category(_ error: MCPProcessHarnessError) -> String {
      switch error {
      case .missingEnvironment(_): "required_environment_missing"
      case .unsafeRunnerEnvironment: "child_environment_not_isolated"
      case .artifactIdentityMismatch: "artifact_identity_mismatch"
      case .legacyConfigurationPresent: "legacy_configuration_present"
      case .dataRootNotIsolated: "data_root_not_isolated"
      case .existingIPCServer: "ipc_endpoint_already_in_use"
      case .processExitedBeforeIPCReady: "service_process_exited_early"
      case .ipcReadinessTimeout: "service_ipc_readiness_timeout"
      case .invalidLocalEndpoint: "local_endpoint_invalid"
      case .invalidCaptureDirectory: "capture_directory_not_isolated"
      case .requestFailed: "http_request_or_status_failure"
      case .malformedResponse: "response_json_or_content_type_invalid"
      case .responseMismatch: "jsonrpc_response_assertion_mismatch"
      }
    }

    private func assertNamedPipeIsAbsent(_ pipeName: String) throws {
      let opened = pipeName.withCString(encodedAs: UTF16.self) { name in
        CreateFileW(
          name,
          DWORD(0x8000_0000) | DWORD(0x4000_0000),
          0,
          nil,
          DWORD(OPEN_EXISTING),
          DWORD(FILE_FLAG_OVERLAPPED),
          nil
        )
      }
      guard let opened else {
        throw MCPProcessHarnessError.existingIPCServer
      }
      guard opened == INVALID_HANDLE_VALUE else {
        _ = CloseHandle(opened)
        throw MCPProcessHarnessError.existingIPCServer
      }
      guard GetLastError() == ERROR_FILE_NOT_FOUND else {
        throw MCPProcessHarnessError.existingIPCServer
      }
    }
  }
#else
  final class MCPWindowsExecutableProcessTests: XCTestCase, @unchecked Sendable {
    func testWindowsPortableExecutableServesModernMCPRoutes() throws {
      throw XCTSkip("This process-level test requires a Windows x64 runner.")
    }
  }
#endif
