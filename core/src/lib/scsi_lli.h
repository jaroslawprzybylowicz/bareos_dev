/*
   BAREOS® - Backup Archiving REcovery Open Sourced

   Copyright (C) 2011-2012 Planets Communications B.V.
   Copyright (C) 2013-2026 Bareos GmbH & Co. KG

   This program is Free Software; you can redistribute it and/or
   modify it under the terms of version three of the GNU Affero General Public
   License as published by the Free Software Foundation and included
   in the file LICENSE.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
   02110-1301, USA.
*/

// Marco van Wieringen, March 2012

#ifndef BAREOS_LIB_SCSI_LLI_H_
#define BAREOS_LIB_SCSI_LLI_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>

// Device Inquiry Response
typedef struct {
#if HAVE_BIG_ENDIAN
  uint8_t peripheralQualifier : 3;
  uint8_t periphrealDeviceType : 5;
  uint8_t RMB : 1;
  uint8_t res_bits_1 : 7;
#else
  uint8_t periphrealDeviceType : 5;
  uint8_t peripheralQualifier : 3;
  uint8_t res_bits_1 : 7;
  uint8_t RMB : 1;
#endif
  uint8_t Version[1];
#if HAVE_BIG_ENDIAN
  uint8_t obs_bits_1 : 2;
  uint8_t NORMACA : 1;
  uint8_t HISUP : 1;
  uint8_t responseDataFormat : 4;
#else
  uint8_t responseDataFormat : 4;
  uint8_t HISUP : 1;
  uint8_t NORMACA : 1;
  uint8_t obs_bits_1 : 2;
#endif
  uint8_t additionalLength[1];
#if HAVE_BIG_ENDIAN
  uint8_t SCCS : 1;
  uint8_t ACC : 1;
  uint8_t TPGS : 2;
  uint8_t threePC : 1;
  uint8_t res_bits_2 : 2;
  uint8_t protect : 1;
  uint8_t obs_bits_2 : 1;
  uint8_t ENCSERV : 1;
  uint8_t VS : 1;
  uint8_t MULTIP : 1;
  uint8_t MCHNGR : 1;
  uint8_t obs_bits_3 : 2;
  uint8_t ADDR16 : 1;
  uint8_t obs_bits_4 : 2;
  uint8_t WBUS16 : 1;
  uint8_t SYNC : 1;
  uint8_t obs_bits_5 : 2;
  uint8_t CMDQUE : 1;
  uint8_t VS2 : 1;
#else
  uint8_t protect : 1;
  uint8_t res_bits_2 : 2;
  uint8_t threePC : 1;
  uint8_t TPGS : 2;
  uint8_t ACC : 1;
  uint8_t SCCS : 1;
  uint8_t ADDR16 : 1;
  uint8_t obs_bits_3 : 2;
  uint8_t MCHNGR : 1;
  uint8_t MULTIP : 1;
  uint8_t VS : 1;
  uint8_t ENCSERV : 1;
  uint8_t obs_bits_2 : 1;
  uint8_t VS2 : 1;
  uint8_t CMDQUE : 1;
  uint8_t obs_bits_5 : 2;
  uint8_t SYNC : 1;
  uint8_t WBUS16 : 1;
  uint8_t obs_bits_4 : 2;
#endif
  uint8_t vendor[8];
  uint8_t productID[16];
  uint8_t productRev[4];
  uint8_t SN[7];
  uint8_t venderUnique[12];
#if HAVE_BIG_ENDIAN
  uint8_t res_bits_3 : 4;
  uint8_t CLOCKING : 2;
  uint8_t QAS : 1;
  uint8_t IUS : 1;
#else
  uint8_t IUS : 1;
  uint8_t QAS : 1;
  uint8_t CLOCKING : 2;
  uint8_t res_bits_3 : 4;
#endif
  uint8_t res_bits_4[1];
  uint8_t versionDescriptor[16];
  uint8_t res_bits_5[22];
  uint8_t copyright[1];
} SCSI_PAGE_INQ;

// Sense Data Response
typedef struct {
#if HAVE_BIG_ENDIAN
  uint8_t valid : 1;
  uint8_t responseCode : 7;
#else
  uint8_t responseCode : 7;
  uint8_t valid : 1;
#endif
  uint8_t res_bits_1;
#if HAVE_BIG_ENDIAN
  uint8_t filemark : 1;
  uint8_t EOM : 1;
  uint8_t ILI : 1;
  uint8_t res_bits_2 : 1;
  uint8_t senseKey : 4;
#else
  uint8_t senseKey : 4;
  uint8_t res_bits_2 : 1;
  uint8_t ILI : 1;
  uint8_t EOM : 1;
  uint8_t filemark : 1;
#endif
  uint8_t information[4];
  uint8_t addSenseLen;
  uint8_t cmdSpecificInfo[4];
  uint8_t addSenseCode;
  uint8_t addSenseCodeQual;
  uint8_t fieldRepUnitCode;
#if HAVE_BIG_ENDIAN
  uint8_t sim : 3; /* system information message */
  uint8_t bpv : 1; /* bit pointer valid */
  uint8_t resvd2 : 2;
  uint8_t cd : 1; /* control/data */
  uint8_t SKSV : 1;
#else
  uint8_t SKSV : 1;
  uint8_t cd : 1; /* control/data */
  uint8_t resvd2 : 2;
  uint8_t bpv : 1; /* bit pointer valid */
  uint8_t sim : 3; /* system information message */
#endif
  uint8_t field[2]; /* field pointer */
  uint8_t addSenseData[109];
} SCSI_PAGE_SENSE;

struct ScsiSenseInfo {
  bool valid{false};
  uint8_t sense_key{0};
  uint8_t asc{0};
  uint8_t ascq{0};

  constexpr bool IsUnitAttention() const noexcept
  {
    return valid && sense_key == 0x06;
  }
};

constexpr ScsiSenseInfo DecodeScsiSense(std::span<const uint8_t> sense) noexcept
{
  if (sense.empty()) { return {}; }
  const uint8_t response_code = sense[0] & 0x7f;
  if (response_code == 0x70 || response_code == 0x71) {
    // Fixed-format sense data (SPC-4 section 4.5.3)
    if (sense.size() < 3) { return {}; }
    ScsiSenseInfo info;
    info.valid = true;
    info.sense_key = sense[2] & 0x0f;
    if (sense.size() >= 8) {
      const std::size_t avail
          = std::min(sense.size(), static_cast<std::size_t>(8u + sense[7]));
      if (avail >= 14) {
        info.asc = sense[12];
        info.ascq = sense[13];
      }
    }
    return info;
  }
  if (response_code == 0x72 || response_code == 0x73) {
    // Descriptor-format sense data (SPC-4 section 4.5.2)
    if (sense.size() < 4) { return {}; }
    return {true, static_cast<uint8_t>(sense[1] & 0x0f), sense[2], sense[3]};
  }
  return {};
}

inline constexpr int kMaxScsiUnitAttentionRetries = 3;

struct ScsiIoResult {
  bool ok{false};
  ScsiSenseInfo sense{};
};

template <typename StepFn, typename OnRetryFn>
constexpr bool RunScsiWithUnitAttentionRetry(StepFn&& step,
                                             OnRetryFn&& on_retry,
                                             int max_retries
                                             = kMaxScsiUnitAttentionRetries)
{
  for (int attempt = 0; attempt <= max_retries; ++attempt) {
    const ScsiIoResult res = step(attempt == max_retries);
    if (res.ok) { return true; }
    if (res.sense.IsUnitAttention() && attempt < max_retries) {
      on_retry(res.sense);
      continue;
    }
    return false;
  }
  return false;
}

bool RecvScsiCmdPage(int fd,
                     const char* device_name,
                     void* cdb,
                     unsigned int cdb_len,
                     void* cmd_page,
                     unsigned int cmd_page_len);
bool send_scsi_cmd_page(int fd,
                        const char* device_name,
                        void* cdb,
                        unsigned int cdb_len,
                        void* cmd_page,
                        unsigned int cmd_page_len);
bool CheckScsiAtEod(int fd);
#endif  // BAREOS_LIB_SCSI_LLI_H_
