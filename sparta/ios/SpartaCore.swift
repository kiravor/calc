import Foundation
import SpartaC

/// The only Swift layer here is the NetworkExtension-facing C ABI adapter.
/// Call stop before replacing a profile; no Go runtime is involved.
public enum SpartaCore {
    public static func start(profile: String, password: String, nodeAddress: String,
                             port: UInt16 = 0, user: String, socksPassword: String) throws -> UInt16 {
        var error = [CChar](repeating: 0, count: 256)
        let status = error.withUnsafeMutableBufferPointer {
            sparta_start(profile, password, nodeAddress, UInt32(port), user,
                         socksPassword, nil, $0.baseAddress, $0.count)
        }
        guard status == 0 else { throw failure(error) }
        return UInt16(sparta_port())
    }

    public static func check(timeoutMilliseconds: UInt32 = 5000) throws {
        var error = [CChar](repeating: 0, count: 256)
        let status = error.withUnsafeMutableBufferPointer {
            sparta_check("http://cp.cloudflare.com/generate_204", timeoutMilliseconds,
                         $0.baseAddress, $0.count)
        }
        guard status == 0 else { throw failure(error) }
    }

    public static func stop() { sparta_stop() }

    private static func failure(_ buffer: [CChar]) -> NSError {
        NSError(domain: "SpartaC", code: 1,
                userInfo: [NSLocalizedDescriptionKey: String(cString: buffer)])
    }
}
