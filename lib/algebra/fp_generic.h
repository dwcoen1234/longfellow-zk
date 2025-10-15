// Copyright 2025 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_GENERIC_H_
#define PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_GENERIC_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>

#include "algebra/nat.h"
#include "algebra/static_string.h"
#include "algebra/sysdep.h"
#include "util/panic.h"

namespace proofs {
struct PrimeFieldTypeTag {};

/*
The Fp_generic class contains the implementation of a finite field.
*/
template <size_t W64, bool optimized_mul, class OPS>
class FpGeneric {
 public:
  // Type alias for a natural number, and the limbs within the nat are public
  // to allow casting and operations.
  using N = Nat<W64>;
  using limb_t = typename N::limb_t;
  using TypeTag = PrimeFieldTypeTag;

  static constexpr size_t kU64 = N::kU64;
  static constexpr size_t kBytes = N::kBytes;
  static constexpr size_t kSubFieldBytes = kBytes;
  static constexpr size_t kBits = N::kBits;
  static constexpr size_t kLimbs = N::kLimbs;

  static constexpr bool kCharacteristicTwo = false;
  static constexpr size_t kNPolyEvaluationPoints = 6;
  N m_;

  /* The Elt struct represented an element in the finite field.
   */
  struct Elt {
    N n;
    bool operator==(const Elt& y) const { return n == y.n; }
    bool operator!=(const Elt& y) const { return !operator==(y); }
  };

  explicit FpGeneric(const N& modulus) : m_(modulus), negm_(N{}) {
    negm_.sub(m_);

    // compute rawhalf = (m + 1) / 2 = floor(m / 2) + 1 since m is odd
    N raw_half = m_;
    raw_half.shiftr(1);
    raw_half.add(N(1));
    raw_half_ = Elt{raw_half};

    mprime_ = -inv_mod_b(m_.limb_[0]);
    rsquare_ = Elt{N(1)};
    for (size_t bits = 0; bits < 2 * kBits; ++bits) {
      add(rsquare_, rsquare_);
    }

    for (uint64_t i = 0; i < sizeof(k_) / sizeof(k_[0]); ++i) {
      // convert k_[i] into montgomery form by calling mul0()
      // directly, since mul() requires k_[0] and k_[1] to be
      // defined
      k_[i] = Elt{N(i)};
      mul0(k_[i].n, rsquare_);
    }

    mone_ = negf(k_[1]);
    half_ = invertf(k_[2]);

    for (size_t i = 0; i < kNPolyEvaluationPoints; ++i) {
      poly_evaluation_points_[i] = of_scalar(i);
      if (i == 0) {
        inv_small_scalars_[i] = zero();
      } else {
        inv_small_scalars_[i] = invertf(poly_evaluation_points_[i]);
      }
    }
  }

  explicit FpGeneric(const StaticString s) : FpGeneric(N(s)) {}

  template <size_t LEN>
  explicit FpGeneric(const char (&s)[LEN]) : FpGeneric(N(s)) {}

  // Hack: works only if OPS::modulus is defined, and will
  // fail to compile otherwise.
  explicit FpGeneric() : FpGeneric(N(OPS::kModulus)) {}

  FpGeneric(const FpGeneric&) = delete;
  FpGeneric& operator=(const FpGeneric&) = delete;

  template <size_t N>
  Elt of_string(const char (&s)[N]) const {
    return of_charp(&s[0]);
  }

  Elt of_string(const StaticString& s) const { return of_charp(s.as_pointer); }

  std::optional<Elt> of_untrusted_string(const char* s) const {
    auto maybe = N::of_untrusted_string(s);
    if (maybe.has_value() && maybe.value() < m_) {
      return to_montgomery(maybe.value());
    } else {
      return std::nullopt;
    }
  }

  // Field arithmetic.  We allow field operations on both Nat and Elt,
  // the idea being that Elt is a Nat in Montgomery form, and
  // Montgomery is just multiplication by a constant.  Thus,
  // we allow addition and subtraction of Nats, and multiplication
  // of Nat by Elt, but not Nat by Nat since we only
  // have a Montgomery multiplier.

  // a += y
  void add(N& a, const N& y) const {
    if (kLimbs == 1) {
      limb_t aa = a.limb_[0], yy = y.limb_[0], mm = m_.limb_[0];
      a.limb_[0] = addcmovc(aa - mm, yy, aa + yy);
    } else {
      limb_t ah = add_limb(kLimbs, a.limb_, y.limb_);
      maybe_minus_m(a.limb_, ah);
    }
  }

  void add(Elt& a, const Elt& y) const { add(a.n, y.n); }

  // a -= y
  //
  void sub(N& a, const N& y) const {
    if (kLimbs == 1) {
      a.limb_[0] = sub_sysdep(a.limb_[0], y.limb_[0], m_.limb_[0]);
    } else {
      limb_t ah = sub_limb(kLimbs, a.limb_, y.limb_);
      maybe_plus_m(a.limb_, ah);
    }
  }

  void sub(Elt& a, const Elt& y) const { sub(a.n, y.n); }

  // x *= y, Montgomery
  void mul(Elt& x, const Elt& y) const {
    if (optimized_mul) {
      if (x == zero() || y == one()) {
        return;
      }
      if (y == zero() || x == one()) {
        x = y;
        return;
      }
    }
    mul0(x.n, y);
  }

  // Nat by Elt
  void mul(N& x, const Elt& y) const { mul0(x, y); }

  // x = -x
  void neg(Elt& x) const {
    Elt y(k_[0]);
    sub(y, x);
    x = y;
  }

  // x = 1/x
  void invert(Elt& x) const { x = invertf(x); }

  // functional interface
  Elt addf(Elt a, const Elt& y) const {
    add(a, y);
    return a;
  }
  Elt subf(Elt a, const Elt& y) const {
    sub(a, y);
    return a;
  }
  Elt mulf(Elt a, const Elt& y) const {
    mul(a, y);
    return a;
  }
  Elt negf(Elt a) const {
    neg(a);
    return a;
  }

  // This is the binary extended gcd algorithm, modified
  // to return the inverse of x.
  Elt invertf(Elt x) const {
    N a = from_montgomery(x);
    N b = m_;
    Elt u = one();
    Elt v = zero();
    while (a != /*zero*/ N{}) {
      if ((a.limb_[0] & 0x1u) == 0) {
        a.shiftr(1);
        byhalf(u);
      } else {
        if (a < b) {  // swap to maintain invariant
          std::swap(a, b);
          std::swap(u, v);
        }
        a.sub(b).shiftr(1);  // a = (a-b)/2
        sub(u, v);
        byhalf(u);
      }
    }
    return v;
  }

  // Reference implementation, unused.
  N from_montgomery_reference(const Elt& x) const {
    Elt r{N(1)};
    mul(r, x);
    return r.n;
  }

  // Optimized implementation of from_montgomery_reference(), exploiting
  // the fact that the multiplicand is Elt{N(1)}.
  N from_montgomery(const Elt& x) const {
    limb_t a[2 * kLimbs + 1];  // uninitialized
    mov(kLimbs, a, x.n.limb_);
    a[kLimbs] = zero_limb<limb_t>();
    for (size_t i = 0; i < kLimbs; ++i) {
      a[i + kLimbs + 1] = zero_limb<limb_t>();
      OPS::reduction_step(&a[i], mprime_, m_);
    }
    maybe_minus_m(a + kLimbs, a[2 * kLimbs]);
    N r;
    mov(kLimbs, r.limb_, a + kLimbs);
    return r;
  }

  Elt to_montgomery(const N& xn) const {
    Elt x{xn};
    mul(x, rsquare_);
    return x;
  }

  bool in_subfield(const Elt& e) const { return true; }

  // The of_scalar methods should only be used on trusted inputs known
  // at compile time to be valid field elements. As a result, they return
  // Elt directly instead of std::optional, and panic if the condition is not
  // satisfied. All untrusted input should be handled via the of_bytes method.
  Elt of_scalar(uint64_t a) const { return of_scalar_field(a); }

  // basis for the binary representation of of_scalar(), so that
  // of_scalar(sum_i b[i] 2^i) = sum_i b[i] beta(i)
  Elt beta(size_t i) const {
    check(i < 64, "i < 64");
    return of_scalar(static_cast<uint64_t>(1) << i);
  }

  Elt of_scalar_field(uint64_t a) const { return of_scalar_field(N(a)); }
  Elt of_scalar_field(const std::array<uint64_t, W64>& a) const {
    return of_scalar_field(N(a));
  }
  Elt of_scalar_field(const N& a) const {
    check(a < m_, "of_scalar must be less than m");
    return to_montgomery(a);
  }

  // Reduction of a Nat<WX> into a field Elt.
  // For optimization purposes, the reduce() algorithm
  // computes a scaled answer which must be normalized at the end.
  // The scale factor is computed by a relatively slow routine
  // reduce_scale(), which returns a special type indexed
  // by WX to avoid confusion.
  template <size_t WX>
  struct ScaleElt {
    Elt e;
  };

  template <size_t WX>
  ScaleElt<WX> reduce_scale() const {
    Elt e = rsquare_;
    for (size_t i = 0; i < Nat<WX>::kBits; ++i) {
      add(e, e);
    }
    return ScaleElt<WX>{e};
  }

  template <size_t WX>
  Elt reduce(const Nat<WX>& x, const ScaleElt<WX>& scale) const {
    Elt r;
    r.n = reduce_nat(x);
    mul(r, scale.e);
    return r;
  }

  template <size_t WX>
  Elt reduce(const Nat<WX>& x) const {
    return reduce(x, reduce_scale<WX>());
  }

  std::optional<Elt> of_bytes_field(const uint8_t ab[/* kBytes */]) const {
    N an = N::of_bytes(ab);
    if (an < m_) {
      return to_montgomery(an);
    } else {
      return std::nullopt;
    }
  }

  void to_bytes_field(uint8_t ab[/* kBytes */], const Elt& x) const {
    from_montgomery(x).to_bytes(ab);
  }

  std::optional<Elt> of_bytes_subfield(const uint8_t ab[/* kBytes */]) const {
    return of_bytes_field(ab);
  }

  void to_bytes_subfield(uint8_t ab[/* kBytes */], const Elt& x) const {
    to_bytes_field(ab, x);
  }

  const Elt& zero() const { return k_[0]; }
  const Elt& one() const { return k_[1]; }
  const Elt& two() const { return k_[2]; }
  const Elt& half() const { return half_; }
  const Elt& mone() const { return mone_; }

  Elt poly_evaluation_point(size_t i) const {
    check(i < kNPolyEvaluationPoints, "i < kNPolyEvaluationPoints");
    return poly_evaluation_points_[i];
  }

  // return (X[k] - X[k - i])^{-1}, were X[i] is the
  // i-th poly evalaluation point.
  Elt newton_denominator(size_t k, size_t i) const {
    check(k < kNPolyEvaluationPoints, "k < kNPolyEvaluationPoints");
    check(i <= k, "i <= k");
    check(k != (k - i), "k != (k - i)");
    return inv_small_scalars_[/* k - (k - i) = */ i];
  }

  // Type for counters.  For prime fields counters and field
  // elements have the same representation, so all conversions
  // are trivial.
  struct CElt {
    Elt e;
  };
  CElt as_counter(uint64_t a) const { return CElt{of_scalar_field(a)}; }

  // Convert a counter into *some* field element such that the counter is
  // zero (as a counter) iff the field element is zero.
  Elt znz_indicator(const CElt& celt) const { return celt.e; }

  // dot product
  struct NatScaledForDot {
    N n;
  };
  NatScaledForDot prescale_for_dot(Elt e) const {
    ScaleElt<W64 + 2> scale = reduce_scale<W64 + 2>();
    mul(e, scale.e);
    return NatScaledForDot{from_montgomery(e)};
  }
  Elt dot(size_t n, const Nat<1> a[/*n*/],
          const NatScaledForDot b[/*n*/]) const {
    Nat<W64 + 2> s{};
    for (size_t i = 0; i < n; ++i) {
      s.mac(a[i], b[i].n);
    }
    return Elt{reduce_nat(s)};
  }

 private:
  void maybe_minus_m(limb_t a[kLimbs], limb_t ah) const {
    limb_t a1[kLimbs];
    mov(kLimbs, a1, negm_.limb_);
    limb_t ah1 = add_limb(kLimbs, a1, a);
    cmovne(kLimbs, a, ah, ah1, a1);
  }
  void maybe_plus_m(limb_t a[kLimbs], limb_t ah) const {
    limb_t a1[kLimbs];
    mov(kLimbs, a1, a);
    (void)add_limb(kLimbs, a1, m_.limb_);
    cmovnz(kLimbs, a, ah, a1);
  }

  void byhalf(Elt& a) const {
    if (a.n.shiftr(1) != 0) {
      // the lost bit is a raw 1, not one() in Montgomery form,
      // hence we must add a raw 1/2, not half().
      add(a, raw_half_);
    }
  }

  // unoptimized montgomery multiplication that does not
  // depend on the constants zero() and one() being defined.
  void mul0(N& x, const Elt& y) const {
    limb_t a[2 * kLimbs + 1];  // uninitialized
    mulstep<true>(a, x.limb_[0], y.n.limb_);
    for (size_t i = 1; i < kLimbs; ++i) {
      mulstep<false>(a + i, x.limb_[i], y.n.limb_);
    }
    maybe_minus_m(a + kLimbs, a[2 * kLimbs]);
    mov(kLimbs, x.limb_, a + kLimbs);
  }

  template <bool first>
  inline void mulstep(limb_t* a, limb_t x, const limb_t y[kLimbs]) const {
    if (kLimbs == 1) {
      // The general case (below) represents the (kLimbs+1)-word
      // product as L+(H<<bitsPerLimb), where in general L and H
      // overlap, requiring two additions.  For kLimbs==1, L and H do
      // not overlap, and we can interpret [L, H] as a single
      // double-precision number.
      a[2] = zero_limb<limb_t>();
      check(first, "mulstep template must be have first=true for 1 limb");
      mulhl(1, a, a + 1, x, y);
      OPS::reduction_step(a, mprime_, m_);
    } else {
      limb_t l[kLimbs], h[kLimbs];
      a[kLimbs + 1] = zero_limb<limb_t>();
      if (first) {
        a[kLimbs] = zero_limb<limb_t>();
        mulhl(kLimbs, a, h, x, y);
      } else {
        mulhl(kLimbs, l, h, x, y);
        accum(kLimbs + 1, a, kLimbs, l);
      }
      accum(kLimbs + 1, a + 1, kLimbs, h);
      OPS::reduction_step(a, mprime_, m_);
    }
  }

  // This method should only be used on static strings known at
  // compile time to be valid field elements.  We make it
  // private to prevent misuse.
  Elt of_charp(const char* s) const {
    Elt a(k_[0]);
    Elt base = of_scalar(10);
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
      s += 2;
      base = of_scalar(16);
    }

    for (; *s; s++) {
      Elt d = of_scalar(digit(*s));
      mul(a, base);
      add(a, d);
    }
    return a;
  }

  // Unscaled reduction of X into a Nat<W64>.  The result
  // must be multiplied by reduce_scale<WX>
  template <size_t WX>
  N reduce_nat(const Nat<WX>& x) const {
    constexpr size_t kLimbsX = Nat<WX>::kLimbs;
    limb_t a[kLimbs + kLimbsX + 1] = {};
    for (size_t i = 0; i < kLimbsX; ++i) {
      accum(kLimbs + 1, &a[i], 1, &x.limb_[i]);
      OPS::reduction_step(&a[i], mprime_, m_);
    }
    maybe_minus_m(a + kLimbsX, a[kLimbs + kLimbsX]);
    N n;
    mov(kLimbs, n.limb_, a + kLimbsX);
    return n;
  }

  N negm_;
  Elt rsquare_;  // 2^(kbits + kBits) mod p
  limb_t mprime_;
  Elt k_[3];  // small constants
  Elt half_;  // 1/2
  Elt raw_half_;
  Elt mone_;  // minus one
  Elt poly_evaluation_points_[kNPolyEvaluationPoints];
  Elt inv_small_scalars_[kNPolyEvaluationPoints];
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_ALGEBRA_FP_GENERIC_H_
