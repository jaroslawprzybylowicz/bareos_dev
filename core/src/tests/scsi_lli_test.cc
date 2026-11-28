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
#include "lib/scsi_lli.h"

#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>

#if defined(HAVE_LINUX_OS) && defined(HAVE_LOWLEVEL_SCSI_INTERFACE)
#  include <fcntl.h>
#  include <scsi/sg.h>
#  include <unistd.h>

extern "C" int __real_ioctl(int fd, unsigned long request, ...);
extern "C" int __wrap_ioctl(int fd, unsigned long request, ...);

namespace {
std::function<int(int, sg_io_hdr_t*)> g_sg_io_handler;
}  // namespace

extern "C" int __wrap_ioctl(int fd, unsigned long request, ...)
{
  va_list ap;
  va_start(ap, request);
  void* arg = va_arg(ap, void*);
  va_end(ap);

  if (request == SG_IO && g_sg_io_handler) {
    return g_sg_io_handler(fd, static_cast<sg_io_hdr_t*>(arg));
  }
  return __real_ioctl(fd, request, arg);
}

namespace {

class ScsiLliLinuxSgIoTest : public ::testing::Test {
 protected:
  void TearDown() override { g_sg_io_handler = nullptr; }
};

TEST_F(ScsiLliLinuxSgIoTest, RecvWithOpenFdPopulatesSgIoAndKeepsFdOpen)
{
  int pipe_fds[2]{-1, -1};
  ASSERT_EQ(pipe(pipe_fds), 0);

  std::array<uint8_t, 12> cdb = {0xa2, 0x20, 0x00, 0x20};
  std::array<uint8_t, 28> page{};
  std::size_t calls = 0;

  g_sg_io_handler = [&](int fd, sg_io_hdr_t* hdr) -> int {
    ++calls;
    EXPECT_EQ(fd, pipe_fds[0]);
    EXPECT_EQ(hdr->interface_id, 'S');
    EXPECT_EQ(hdr->dxfer_direction, SG_DXFER_FROM_DEV);
    EXPECT_EQ(hdr->cmdp, cdb.data());
    EXPECT_EQ(hdr->cmd_len, cdb.size());
    EXPECT_EQ(hdr->dxferp, reinterpret_cast<char*>(page.data()));
    EXPECT_EQ(hdr->dxfer_len, page.size());
    EXPECT_NE(hdr->sbp, nullptr);
    EXPECT_EQ(hdr->mx_sb_len, sizeof(SCSI_PAGE_SENSE));
    static_cast<uint8_t*>(hdr->dxferp)[0] = 0x5a;
    static_cast<uint8_t*>(hdr->dxferp)[27] = 0xa5;
    hdr->info = SG_INFO_OK;
    return 0;
  };

  EXPECT_TRUE(RecvScsiCmdPage(pipe_fds[0], "/unused", cdb.data(), cdb.size(),
                              page.data(), page.size()));
  EXPECT_EQ(calls, 1u);
  EXPECT_EQ(page[0], 0x5a);
  EXPECT_EQ(page[27], 0xa5);
  EXPECT_NE(fcntl(pipe_fds[0], F_GETFD), -1);

  close(pipe_fds[0]);
  close(pipe_fds[1]);
}

TEST_F(ScsiLliLinuxSgIoTest, SendWithOpenFdFailsAndKeepsFdOpenOnErrors)
{
  int pipe_fds[2]{-1, -1};
  ASSERT_EQ(pipe(pipe_fds), 0);

  std::array<uint8_t, 12> cdb = {0xb5, 0x20, 0x00, 0x10};
  std::array<uint8_t, 20> page{};

  g_sg_io_handler = [&](int fd, sg_io_hdr_t* hdr) -> int {
    EXPECT_EQ(fd, pipe_fds[0]);
    EXPECT_EQ(hdr->dxfer_direction, SG_DXFER_TO_DEV);
    errno = EIO;
    return -1;
  };
  EXPECT_FALSE(send_scsi_cmd_page(pipe_fds[0], "/unused", cdb.data(),
                                  cdb.size(), page.data(), page.size()));
  EXPECT_NE(fcntl(pipe_fds[0], F_GETFD), -1);

  g_sg_io_handler = [&](int fd, sg_io_hdr_t* hdr) -> int {
    EXPECT_EQ(fd, pipe_fds[0]);
    EXPECT_EQ(hdr->dxfer_direction, SG_DXFER_TO_DEV);
    hdr->info = SG_INFO_CHECK;
    return 0;
  };
  EXPECT_FALSE(send_scsi_cmd_page(pipe_fds[0], "/unused", cdb.data(),
                                  cdb.size(), page.data(), page.size()));
  EXPECT_NE(fcntl(pipe_fds[0], F_GETFD), -1);

  close(pipe_fds[0]);
  close(pipe_fds[1]);
}

TEST_F(ScsiLliLinuxSgIoTest, FdMinusOneOpensAndClosesDeviceOnAllPaths)
{
  char tmpl[] = "/tmp/bareos_scsi_lli_test_XXXXXX";
  const int tmp_fd = mkstemp(tmpl);
  ASSERT_GE(tmp_fd, 0);
  close(tmp_fd);

  std::array<uint8_t, 6> cdb{};
  std::array<uint8_t, 16> page{};

  int captured_fd = -1;
  g_sg_io_handler = [&](int fd, sg_io_hdr_t* hdr) -> int {
    captured_fd = fd;
    EXPECT_NE(fcntl(fd, F_GETFD), -1);
    hdr->info = SG_INFO_OK;
    return 0;
  };
  EXPECT_TRUE(RecvScsiCmdPage(-1, tmpl, cdb.data(), cdb.size(), page.data(),
                              page.size()));
  ASSERT_GE(captured_fd, 0);
  errno = 0;
  EXPECT_EQ(fcntl(captured_fd, F_GETFD), -1);
  EXPECT_EQ(errno, EBADF);

  captured_fd = -1;
  g_sg_io_handler = [&](int fd, sg_io_hdr_t*) -> int {
    captured_fd = fd;
    EXPECT_NE(fcntl(fd, F_GETFD), -1);
    errno = EIO;
    return -1;
  };
  EXPECT_FALSE(send_scsi_cmd_page(-1, tmpl, cdb.data(), cdb.size(), page.data(),
                                  page.size()));
  ASSERT_GE(captured_fd, 0);
  errno = 0;
  EXPECT_EQ(fcntl(captured_fd, F_GETFD), -1);
  EXPECT_EQ(errno, EBADF);

  captured_fd = -1;
  g_sg_io_handler = [&](int fd, sg_io_hdr_t* hdr) -> int {
    captured_fd = fd;
    EXPECT_NE(fcntl(fd, F_GETFD), -1);
    hdr->info = SG_INFO_CHECK;
    return 0;
  };
  EXPECT_FALSE(send_scsi_cmd_page(-1, tmpl, cdb.data(), cdb.size(), page.data(),
                                  page.size()));
  ASSERT_GE(captured_fd, 0);
  errno = 0;
  EXPECT_EQ(fcntl(captured_fd, F_GETFD), -1);
  EXPECT_EQ(errno, EBADF);

  unlink(tmpl);
}

TEST_F(ScsiLliLinuxSgIoTest, FdMinusOneWithMissingDeviceFailsWithoutIoctl)
{
  std::size_t calls = 0;
  g_sg_io_handler = [&](int, sg_io_hdr_t*) -> int {
    ++calls;
    return 0;
  };

  std::array<uint8_t, 6> cdb{};
  std::array<uint8_t, 16> page{};
  EXPECT_FALSE(RecvScsiCmdPage(-1, "/nonexistent/bareos_scsi_lli_missing_dev",
                               cdb.data(), cdb.size(), page.data(),
                               page.size()));
  EXPECT_EQ(calls, 0u);
}


TEST_F(ScsiLliLinuxSgIoTest, RetriesTransientUnitAttentionOnSameFdAndSucceeds)
{
  char tmpl[] = "/tmp/bareos_scsi_lli_ua_XXXXXX";
  const int tmp_fd = mkstemp(tmpl);
  ASSERT_GE(tmp_fd, 0);
  close(tmp_fd);

  std::array<uint8_t, 6> cdb{};
  std::array<uint8_t, 16> page{};
  int first_fd = -1;
  std::size_t calls = 0;

  g_sg_io_handler = [&](int fd, sg_io_hdr_t* hdr) -> int {
    ++calls;
    if (calls == 1) {
      first_fd = fd;
    } else {
      EXPECT_EQ(fd, first_fd);
    }
    if (calls <= 3) {
      constexpr std::array<uint8_t, 18> kUa
          = {0x70, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
             0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00};
      std::memcpy(hdr->sbp, kUa.data(), kUa.size());
      hdr->sb_len_wr = kUa.size();
      hdr->info = SG_INFO_CHECK;
      return 0;
    }
    hdr->info = SG_INFO_OK;
    return 0;
  };

  EXPECT_TRUE(RecvScsiCmdPage(-1, tmpl, cdb.data(), cdb.size(), page.data(),
                              page.size()));
  EXPECT_EQ(calls, 4u);
  ASSERT_GE(first_fd, 0);
  errno = 0;
  EXPECT_EQ(fcntl(first_fd, F_GETFD), -1);
  EXPECT_EQ(errno, EBADF);
  unlink(tmpl);
}

TEST_F(ScsiLliLinuxSgIoTest, FailsAfterMaxUnitAttentionRetriesAndClosesFd)
{
  char tmpl[] = "/tmp/bareos_scsi_lli_uafail_XXXXXX";
  const int tmp_fd = mkstemp(tmpl);
  ASSERT_GE(tmp_fd, 0);
  close(tmp_fd);

  std::array<uint8_t, 6> cdb{};
  std::array<uint8_t, 16> page{};
  int captured_fd = -1;
  std::size_t calls = 0;

  g_sg_io_handler = [&](int fd, sg_io_hdr_t* hdr) -> int {
    ++calls;
    captured_fd = fd;
    constexpr std::array<uint8_t, 18> kUa
        = {0x70, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
           0x00, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::memcpy(hdr->sbp, kUa.data(), kUa.size());
    hdr->sb_len_wr = kUa.size();
    hdr->info = SG_INFO_CHECK;
    return 0;
  };

  EXPECT_FALSE(send_scsi_cmd_page(-1, tmpl, cdb.data(), cdb.size(), page.data(),
                                  page.size()));
  EXPECT_EQ(calls, 4u);
  ASSERT_GE(captured_fd, 0);
  errno = 0;
  EXPECT_EQ(fcntl(captured_fd, F_GETFD), -1);
  EXPECT_EQ(errno, EBADF);
  unlink(tmpl);
}

TEST_F(ScsiLliLinuxSgIoTest, DoesNotRetryNonUnitAttentionSense)
{
  int pipe_fds[2]{-1, -1};
  ASSERT_EQ(pipe(pipe_fds), 0);

  std::array<uint8_t, 6> cdb{};
  std::array<uint8_t, 16> page{};
  std::size_t calls = 0;

  g_sg_io_handler = [&](int, sg_io_hdr_t* hdr) -> int {
    ++calls;
    constexpr std::array<uint8_t, 8> kIllegalReq
        = {0x72, 0x05, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::memcpy(hdr->sbp, kIllegalReq.data(), kIllegalReq.size());
    hdr->sb_len_wr = kIllegalReq.size();
    hdr->info = SG_INFO_CHECK;
    return 0;
  };

  EXPECT_FALSE(send_scsi_cmd_page(pipe_fds[0], "/unused", cdb.data(),
                                  cdb.size(), page.data(), page.size()));
  EXPECT_EQ(calls, 1u);
  EXPECT_NE(fcntl(pipe_fds[0], F_GETFD), -1);
  close(pipe_fds[0]);
  close(pipe_fds[1]);
}

}  // namespace
#endif

namespace {

constexpr std::array<uint8_t, 18> kFixedUnitAttentionSense
    = {0x70, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00,
       0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00};
constexpr ScsiSenseInfo kDecodedUa = DecodeScsiSense(kFixedUnitAttentionSense);
static_assert(kDecodedUa.valid);
static_assert(kDecodedUa.sense_key == 0x06);
static_assert(kDecodedUa.asc == 0x28);
static_assert(kDecodedUa.ascq == 0x00);

constexpr std::array<uint8_t, 18> kShortAdditionalLenSense
    = {0x70, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
       0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00};
constexpr ScsiSenseInfo kDecodedShort
    = DecodeScsiSense(kShortAdditionalLenSense);
static_assert(kDecodedShort.valid);
static_assert(kDecodedShort.sense_key == 0x06);
static_assert(kDecodedShort.asc == 0x00);
static_assert(kDecodedShort.ascq == 0x00);

constexpr std::array<uint8_t, 8> kDescriptorIllegalReqSense
    = {0x72, 0x05, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00};
constexpr ScsiSenseInfo kDecodedDesc
    = DecodeScsiSense(kDescriptorIllegalReqSense);
static_assert(kDecodedDesc.valid);
static_assert(kDecodedDesc.sense_key == 0x05);
static_assert(kDecodedDesc.asc == 0x24);
static_assert(kDecodedDesc.ascq == 0x00);

TEST(ScsiLliSenseTest, DecodeInvalidOrEmptySenseReturnsInvalid)
{
  constexpr std::array<uint8_t, 4> kUnknown = {0x00, 0x06, 0x28, 0x00};
  EXPECT_FALSE(DecodeScsiSense({}).valid);
  EXPECT_FALSE(DecodeScsiSense(kUnknown).valid);
}

static_assert(kDecodedUa.IsUnitAttention());
static_assert(!kDecodedDesc.IsUnitAttention());

TEST(ScsiLliSenseTest, HelperPassesFinalAttemptFlagOnRetries)
{
  std::size_t calls = 0;
  std::size_t retries_logged = 0;
  const bool ok = RunScsiWithUnitAttentionRetry(
      [&](bool is_final_attempt) -> ScsiIoResult {
        ++calls;
        EXPECT_EQ(is_final_attempt, calls == 4);
        if (calls <= 3) { return {false, {true, 0x06, 0x28, 0x00}}; }
        return {true, {}};
      },
      [&](const ScsiSenseInfo&) { ++retries_logged; });
  EXPECT_TRUE(ok);
  EXPECT_EQ(calls, 4u);
  EXPECT_EQ(retries_logged, 3u);
}

}  // namespace
