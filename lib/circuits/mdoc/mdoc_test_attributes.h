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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_TEST_ATTRIBUTES_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_TEST_ATTRIBUTES_H_

#include "circuits/mdoc/mdoc_zk.h"

namespace proofs {
namespace test {
static const RequestedAttribute age_over_18 = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', '1'},
    .id = {'a', 'g', 'e', '_', 'o', 'v', 'e', 'r', '_', '1', '8'},
    .cbor_value = {0xf5},
    .namespace_len = 17,
    .id_len = 11,
    .cbor_value_len = 1};

static const RequestedAttribute europa_age_over_18 = {
    .namespace_id = {'e', 'u', '.', 'e', 'u', 'r', 'o', 'p', 'a', '.', 'e',
                     'c', '.', 'a', 'v', '.', '1'},
    .id = {'a', 'g', 'e', '_', 'o', 'v', 'e', 'r', '_', '1', '8'},
    .cbor_value = {0xf5},
    .namespace_len = 17,
    .id_len = 11,
    .cbor_value_len = 1};

static const RequestedAttribute not_over_18 = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', '1'},
    .id = {'a', 'g', 'e', '_', 'o', 'v', 'e', 'r', '_', '1', '8'},
    .cbor_value = {0xf4},
    .id_len = 11,
    .cbor_value_len = 1};

static const RequestedAttribute age_birth_year = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', '1'},
    .id = {'a', 'g', 'e', '_', 'b', 'i', 'r', 't', 'h', '_', 'y', 'e', 'a',
           'r'},
    .cbor_value = {0x19, 0x07, 0xB0},
    .namespace_len = 17,
    .id_len = 14,
    .cbor_value_len = 3};

static const RequestedAttribute familyname_mustermann = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', '1'},
    .id = {'f', 'a', 'm', 'i', 'l', 'y', '_', 'n', 'a', 'm', 'e'},
    .cbor_value = {0x6A, 'M', 'u', 's', 't', 'e', 'r', 'm', 'a', 'n', 'n'},
    .namespace_len = 17,
    .id_len = 11,
    .cbor_value_len = 11};

static const RequestedAttribute birthdate_1971_09_01 = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', '1'},
    .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
    .cbor_value = {0xD9, 0x03, 0xEC, 0x6A, '1', '9', '7', '1', '-', '0', '9',
                   '-', '0', '1'},
    .namespace_len = 17,
    .id_len = 10,
    .cbor_value_len = 14};

static const RequestedAttribute birthdate_1998_09_04 = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', '1'},
    .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
    .cbor_value = {0xD9, 0x03, 0xEC, 0x6A, '1', '9', '9', '8', '-', '0', '9',
                   '-', '0', '4'},
    .namespace_len = 17,
    .id_len = 10,
    .cbor_value_len = 14};

static const RequestedAttribute birthdate_1968_04_27 = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', '1'},
    .id = {'b', 'i', 'r', 't', 'h', '_', 'd', 'a', 't', 'e'},
    .cbor_value = {0xD9, 0x03, 0xEC, 0x6A, '1', '9', '6', '8', '-', '0', '4',
                   '-', '2', '7'},
    .namespace_len = 17,
    .id_len = 10,
    .cbor_value_len = 14};

static const RequestedAttribute height_175 = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', '1'},
    .id = {'h', 'e', 'i', 'g', 'h', 't'},
    .cbor_value = {0x18, 0xaf},
    .namespace_len = 17,
    .id_len = 6,
    .cbor_value_len = 2};

static const RequestedAttribute issue_date_2024_03_15 = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', '1'},
    .id = {'i', 's', 's', 'u', 'e', '_', 'd', 'a', 't', 'e'},
    .cbor_value = {0xD9, 0x03, 0xEC, 0x6A, '2', '0', '2', '4', '-', '0', '3',
                   '-', '1', '5'},
    .namespace_len = 17,
    .id_len = 10,
    .cbor_value_len = 14};

static const RequestedAttribute issue_date_2025_07_21 = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', '1'},
    .id = {'i', 's', 's', 'u', 'e', '_', 'd', 'a', 't', 'e'},
    .cbor_value = {0xc0, 0x74, '2', '0', '2', '5', '-', '0', '7', '-', '2',
                   '1',  'T',  '0', '4', ':', '0', '0', ':', '0', '0', 'Z'},
    .namespace_len = 17,
    .id_len = 10,
    .cbor_value_len = 22};

static const RequestedAttribute aamva_name_suffix_mr = {
    .namespace_id = {'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1', '8', '0', '1',
                     '3', '.', '5', '.', 'a', 'a', 'm', 'v', 'a'},
    .id = {'n', 'a', 'm', 'e', '_', 's', 'u', 'f', 'f', 'i', 'x'},
    .cbor_value = {0x63, 'M', 'r', '.'},
    .namespace_len = 21,
    .id_len = 11,
    .cbor_value_len = 4};

}  // namespace test
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_MDOC_MDOC_TEST_ATTRIBUTES_H_
