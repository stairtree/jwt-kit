//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import CJWTKitBoringSSL

/// A wrapper around BoringSSL's EC_GROUP object that handles reference counting and
/// liveness.
@usableFromInline
class BoringSSLEllipticCurveGroup {
    /* private but usableFromInline */ @usableFromInline var _group: OpaquePointer

    @usableFromInline
    init(_ curve: Curve) throws {
        guard let group = CJWTKitBoringSSL_EC_GROUP_new_by_curve_name(curve.cName) else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.internalError)
        }

        self._group = group
    }

    deinit {
        CJWTKitBoringSSL_EC_GROUP_free(self._group)
    }
}

// MARK: - Helpers

extension BoringSSLEllipticCurveGroup {
    @usableFromInline
    var coordinateByteCount: Int {
        return (Int(CJWTKitBoringSSL_EC_GROUP_get_degree(self._group)) + 7) / 8
    }

    @usableFromInline
    func makeUnsafeOwnedECKey() throws -> OpaquePointer {
        guard let key = CJWTKitBoringSSL_EC_KEY_new(),
            CJWTKitBoringSSL_EC_KEY_set_group(key, self._group) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.internalError)
        }

        return key
    }

    @inlinable
    func withUnsafeGroupPointer<T>(_ body: (OpaquePointer) throws -> T) rethrows -> T {
        return try body(self._group)
    }

    @usableFromInline
    var order: ArbitraryPrecisionInteger {
        // Groups must have an order.
        let baseOrder = CJWTKitBoringSSL_EC_GROUP_get0_order(self._group)!
        return try! ArbitraryPrecisionInteger(copying: baseOrder)
    }

    /// An elliptic curve can be represented in a Weierstrass form: y² = x³ + ax + b. This
    /// property provides the values of a and b on the curve.
    @usableFromInline
    var weierstrassCoefficients: (field: ArbitraryPrecisionInteger, a: ArbitraryPrecisionInteger, b: ArbitraryPrecisionInteger) {
        var field = ArbitraryPrecisionInteger()
        var a = ArbitraryPrecisionInteger()
        var b = ArbitraryPrecisionInteger()

        let rc = field.withUnsafeMutableBignumPointer { fieldPtr in
            a.withUnsafeMutableBignumPointer { aPtr in
                b.withUnsafeMutableBignumPointer { bPtr in
                    CJWTKitBoringSSL_EC_GROUP_get_curve_GFp(self._group, fieldPtr, aPtr, bPtr, nil)
                }
            }
        }
        precondition(rc == 1, "Unable to extract curve weierstrass parameters")

        return (field: field, a: a, b: b)
    }
}

