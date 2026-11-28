/*
   BAREOS® - Backup Archiving REcovery Open Sourced

   Copyright (C) 2026 Bareos GmbH & Co. KG

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

#include "gtest/gtest.h"
#include "include/bareos.h"
#include "lib/scsi_crypto.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace {

struct CapturedScsiCall {
  int fd{-1};
  std::string device_name;
  std::vector<uint8_t> cdb;
  std::vector<uint8_t> page;
};

CapturedScsiCall g_last_send;
CapturedScsiCall g_last_recv;
std::function<bool(void*, unsigned int)> g_recv_filler;

}  // namespace

bool send_scsi_cmd_page(int fd,
                        const char* device_name,
                        void* cdb,
                        unsigned int cdb_len,
                        void* cmd_page,
                        unsigned int cmd_page_len)
{
  const auto* cdb_bytes = static_cast<const uint8_t*>(cdb);
  const auto* page_bytes = static_cast<const uint8_t*>(cmd_page);
  g_last_send.fd = fd;
  g_last_send.device_name = device_name ? device_name : "";
  g_last_send.cdb.assign(cdb_bytes, cdb_bytes + cdb_len);
  g_last_send.page.assign(page_bytes, page_bytes + cmd_page_len);
  return true;
}

bool RecvScsiCmdPage(int fd,
                     const char* device_name,
                     void* cdb,
                     unsigned int cdb_len,
                     void* cmd_page,
                     unsigned int cmd_page_len)
{
  const auto* cdb_bytes = static_cast<const uint8_t*>(cdb);
  g_last_recv.fd = fd;
  g_last_recv.device_name = device_name ? device_name : "";
  g_last_recv.cdb.assign(cdb_bytes, cdb_bytes + cdb_len);
  g_last_recv.page.resize(cmd_page_len);
  if (g_recv_filler) { return g_recv_filler(cmd_page, cmd_page_len); }
  return true;
}

#ifdef HAVE_LOWLEVEL_SCSI_INTERFACE
namespace {

class ScsiCryptoWireTest : public ::testing::Test {
 protected:
  void SetUp() override
  {
    g_last_send = {};
    g_last_recv = {};
    g_recv_filler = nullptr;
  }
};

TEST_F(ScsiCryptoWireTest, ClearScsiEncryptionKeyWireBytes)
{
  ASSERT_TRUE(ClearScsiEncryptionKey(42, "/dev/sg99"));
  EXPECT_EQ(g_last_send.fd, 42);
  EXPECT_EQ(g_last_send.device_name, "/dev/sg99");

  const std::vector<uint8_t> expected_cdb = {
      0xb5, 0x20, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00};
  EXPECT_EQ(g_last_send.cdb, expected_cdb);

  ASSERT_EQ(g_last_send.page.size(), 20u);
  EXPECT_EQ(g_last_send.page[0], 0x00);
  EXPECT_EQ(g_last_send.page[1], 0x10);
  EXPECT_EQ(g_last_send.page[2], 0x00);
  EXPECT_EQ(g_last_send.page[3], 0x10);  // 16-byte header payload
  EXPECT_EQ(g_last_send.page[4], 0x40);  // ALL_I_T_NEXUS
  EXPECT_EQ(g_last_send.page[5], 0x40);  // CEEM = NO_ENCR_CHECK, CKOD = 0
  EXPECT_EQ(g_last_send.page[6], SPP_ENCR_MODE_DISABLE);
  EXPECT_EQ(g_last_send.page[7], SPP_DECR_MODE_DISABLE);
  EXPECT_EQ(g_last_send.page[8], 0x01);
  EXPECT_EQ(g_last_send.page[9], SPP_KAD_KEY_FORMAT_NORMAL);
  EXPECT_EQ(g_last_send.page[10], 0x00);
  EXPECT_EQ(g_last_send.page[18], 0x00);
  EXPECT_EQ(g_last_send.page[19], 0x00);  // keyLength = 0
}

TEST_F(ScsiCryptoWireTest, SetScsiEncryptionKeyWireBytes)
{
  std::array<char, 33> key_str{};
  for (std::size_t i = 0; i < 32; ++i) {
    key_str[i] = static_cast<char>('A' + (i % 26));
  }

  ASSERT_TRUE(SetScsiEncryptionKey(17, "/dev/sg99", key_str.data()));
  EXPECT_EQ(g_last_send.fd, 17);
  EXPECT_EQ(g_last_send.device_name, "/dev/sg99");

  const std::vector<uint8_t> expected_cdb = {
      0xb5, 0x20, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00};
  EXPECT_EQ(g_last_send.cdb, expected_cdb);

  ASSERT_EQ(g_last_send.page.size(), 52u);
  EXPECT_EQ(g_last_send.page[0], 0x00);
  EXPECT_EQ(g_last_send.page[1], 0x10);
  EXPECT_EQ(g_last_send.page[2], 0x00);
  EXPECT_EQ(g_last_send.page[3], 0x30);
  EXPECT_EQ(g_last_send.page[4], 0x40);  // ALL_I_T_NEXUS
  EXPECT_EQ(g_last_send.page[5], 0x40);  // CEEM = NO_ENCR_CHECK, CKOD = 0
  EXPECT_EQ(g_last_send.page[6], SPP_ENCR_MODE_ENCRYPT);
  EXPECT_EQ(g_last_send.page[7], SPP_DECR_MODE_MIXED);
  EXPECT_EQ(g_last_send.page[8], 0x01);
  EXPECT_EQ(g_last_send.page[9], 0x00);
  EXPECT_EQ(g_last_send.page[10], 0x00);
  EXPECT_EQ(g_last_send.page[18], 0x00);
  EXPECT_EQ(g_last_send.page[19], 0x20);
  for (std::size_t i = 0; i < 31; ++i) {
    EXPECT_EQ(g_last_send.page[20 + i], static_cast<uint8_t>(key_str[i]));
  }
  EXPECT_EQ(g_last_send.page[51], 0x00);  // bstrncpy NUL terminator
}

TEST_F(ScsiCryptoWireTest, SpinQueriesEmitExpectedCdbsAndParseStatus)
{
  const std::vector<uint8_t> expected_des_cdb = {
      0xa2, 0x20, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x20, 0x04, 0x00, 0x00};
  const std::vector<uint8_t> expected_nbes_cdb = {
      0xa2, 0x20, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x20, 0x04, 0x00, 0x00};

  g_recv_filler = [](void* buf, unsigned int len) {
    EXPECT_EQ(len, sizeof(SPP_PAGE_BUFFER));
    auto* des = static_cast<SPP_PAGE_DES*>(buf);
    des->encryptionMode = SPP_ENCR_MODE_ENCRYPT;
    des->decryptionMode = SPP_DECR_MODE_MIXED;
    des->VCELB = 1;
    return true;
  };

  POOLMEM* status = GetPoolMemory(PM_MESSAGE);
  EXPECT_GT(GetScsiDriveEncryptionStatus(9, "/dev/sg99", status, 0), 0);
  EXPECT_EQ(g_last_recv.cdb, expected_des_cdb);
  EXPECT_NE(std::strstr(status, "Encryption Mode: Encrypt"), nullptr);

  EXPECT_TRUE(IsScsiEncryptionEnabled(9, "/dev/sg99"));
  EXPECT_EQ(g_last_recv.cdb, expected_des_cdb);

  EXPECT_TRUE(NeedScsiCryptoKey(9, "/dev/sg99", /*use_drive_status=*/true));
  EXPECT_EQ(g_last_recv.cdb, expected_des_cdb);

  g_recv_filler = [](void* buf, unsigned int len) {
    EXPECT_EQ(len, sizeof(SPP_PAGE_BUFFER));
    auto* nbes = static_cast<SPP_PAGE_NBES*>(buf);
    nbes->encryptionStatus = SPP_ENCR_STATUS_ENCR_NOT_AVAIL;
    return true;
  };

  EXPECT_GT(GetScsiVolumeEncryptionStatus(9, "/dev/sg99", status, 0), 0);
  EXPECT_EQ(g_last_recv.cdb, expected_nbes_cdb);

  EXPECT_TRUE(NeedScsiCryptoKey(9, "/dev/sg99", /*use_drive_status=*/false));
  EXPECT_EQ(g_last_recv.cdb, expected_nbes_cdb);
  FreePoolMemory(status);
}

TEST_F(ScsiCryptoWireTest, NullKeyRejectedAndCkodBuilderSetsBit)
{
  EXPECT_FALSE(SetScsiEncryptionKey(17, "/dev/sg99", nullptr));
  EXPECT_TRUE(g_last_send.cdb.empty());

  constexpr std::array<uint8_t, SPP_KEY_LENGTH> kKey{};
  const SPP_PAGE_SDE ckod_page
      = BuildSetDataEncryptionPage(kKey, 0x01, /*ckod=*/true);
  std::array<uint8_t, sizeof(SPP_PAGE_SDE)> wire{};
  std::memcpy(wire.data(), &ckod_page, wire.size());
  EXPECT_EQ(wire[5], 0x44);  // CEEM = NO_ENCR_CHECK (0x40) | CKOD (0x04)
}

}  // namespace
#endif
