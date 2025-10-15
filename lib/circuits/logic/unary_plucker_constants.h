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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_UNARY_PLUCKER_CONSTANTS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_UNARY_PLUCKER_CONSTANTS_H_
#include <stddef.h>
#include <stdint.h>

#include "circuits/logic/bit_plucker_constants.h"
#include "util/panic.h"

namespace proofs {
template <class Field, size_t NJ>
struct unary_plucker_point {
  using Elt = typename Field::Elt;
  static constexpr size_t kN = NJ + 1;

  Elt operator()(size_t j, const Field& F) const {
    check(j <= NJ, "j <= NJ in unary_plucker_point");
    check(j < kN, "j < N in unary_plucker_point");
    return bit_plucker_point<Field, kN>()(j, F);
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_LOGIC_UNARY_PLUCKER_CONSTANTS_H_
