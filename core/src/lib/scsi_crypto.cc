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

/*
 * Low level SCSI interface for SCSI crypto services
 *
 * Marco van Wieringen, March 2012
 */

#include "include/bareos.h"

/* Forward referenced functions */

static void IndentStatusMsg(POOLMEM*& status, const char* msg, int indent);

#include "lib/scsi_crypto.h"

#ifdef HAVE_LOWLEVEL_SCSI_INTERFACE

/*
 * Clear an encryption key used by a tape drive
 * using a lowlevel SCSI interface.
 *
 * The device is sent a:
 * - SPOUT Security Protocol OUT SCSI CDB. (0xB5)
 * - SPOUT Set Data Encryption Page (0x10), 20 bytes (keyLength = 0).
 */
bool ClearScsiEncryptionKey(int fd, const char* device_name)
{
  auto page = BuildClearDataEncryptionPage();
  auto cdb
      = BuildScsiSecurityCdb(SCSI_SPOUT_OPCODE, SPOUT_SET_DATA_ENCRYPTION_PAGE,
                             static_cast<uint32_t>(page.size()));
  return send_scsi_cmd_page(fd, device_name, &cdb, sizeof(cdb), page.data(),
                            static_cast<unsigned int>(page.size()));
}

/*
 * Set an encryption key used by a tape drive
 * using a lowlevel SCSI interface.
 *
 * The device is sent a:
 * - SPOUT Security Protocol OUT SCSI CDB. (0xB5)
 * - SPOUT Set Data Encryption Page (0x10).
 */
bool SetScsiEncryptionKey(int fd, const char* device_name, char* encryption_key)
{
  if (!encryption_key) { return false; }

  std::array<uint8_t, SPP_KEY_LENGTH> key_bytes{};
  bstrncpy(reinterpret_cast<char*>(key_bytes.data()), encryption_key,
           SPP_KEY_LENGTH);

  SPP_PAGE_SDE sps = BuildSetDataEncryptionPage(key_bytes);
  auto cdb
      = BuildScsiSecurityCdb(SCSI_SPOUT_OPCODE, SPOUT_SET_DATA_ENCRYPTION_PAGE,
                             static_cast<uint32_t>(sizeof(sps)));
  return send_scsi_cmd_page(fd, device_name, &cdb, sizeof(cdb), &sps,
                            sizeof(sps));
}

/*
 * Request the encryption state of a drive
 * using a lowlevel SCSI interface.
 *
 * The device is send a:
 * - SPIN Security Protocol IN SCSI CDB. (0xA2)
 * - SPIN Get Data Encryption Status page. (0x20)
 *
 * The return data is interpreted and a status report is build.
 */
int GetScsiDriveEncryptionStatus(int fd,
                                 const char* device_name,
                                 POOLMEM*& status,
                                 int indent)
{
  SPP_PAGE_BUFFER cmd_page{};
  auto cdb = BuildScsiSecurityCdb(SCSI_SPIN_OPCODE, SPIN_DATA_ENCR_STATUS_PAGE,
                                  static_cast<uint32_t>(sizeof(cmd_page)));

  // Retrieve the drive encryption status.
  if (!RecvScsiCmdPage(fd, device_name, &cdb, sizeof(cdb), &cmd_page,
                       sizeof(cmd_page))) {
    return 0;
  }

  /* We got a response which should contain a SPP_PAGE_DES.
   * Create a pointer to the beginning of the generic
   * cmd_page structure. */
  SPP_PAGE_DES* spd = (SPP_PAGE_DES*)&cmd_page;

  PmStrcpy(status, "");
  IndentStatusMsg(status, T_("Drive encryption status:\n"), indent);

  // See what encryption mode is enabled.
  switch (spd->encryptionMode) {
    case SPP_ENCR_MODE_DISABLE:
      IndentStatusMsg(status, T_("Encryption Mode: Disabled\n"), indent + 3);
      break;
    case SPP_ENCR_MODE_EXTERNAL:
      IndentStatusMsg(status, T_("Encryption Mode: External\n"), indent + 3);
      break;
    case SPP_ENCR_MODE_ENCRYPT:
      IndentStatusMsg(status, T_("Encryption Mode: Encrypt\n"), indent + 3);
      break;
    default:
      break;
  }

  // See what decryption mode is enabled.
  switch (spd->decryptionMode) {
    case SPP_DECR_MODE_DISABLE:
      IndentStatusMsg(status, T_("Decryption Mode: Disabled\n"), indent + 3);
      break;
    case SPP_DECR_MODE_RAW:
      IndentStatusMsg(status, T_("Decryption Mode: Raw\n"), indent + 3);
      break;
    case SPP_DECR_MODE_DECRYPT:
      IndentStatusMsg(status, T_("Decryption Mode: Decrypt\n"), indent + 3);
      break;
    case SPP_DECR_MODE_MIXED:
      IndentStatusMsg(status, T_("Decryption Mode: Mixed\n"), indent + 3);
      break;
    default:
      break;
  }

  // See if RDMD is enabled.
  if (spd->RDMD) {
    IndentStatusMsg(status,
                    T_("Raw Decryption Mode Disabled (RDMD): Enabled\n"),
                    indent + 3);
  } else {
    IndentStatusMsg(status,
                    T_("Raw Decryption Mode Disabled (RDMD): Disabled\n"),
                    indent + 3);
  }

  // See what Check External Encryption Mode Status is set.
  switch (spd->CEEMS) {
    case SPP_CEEM_NO_ENCR_CHECK:
      IndentStatusMsg(
          status, T_("Check External Encryption Mode Status (CEEMS) : No\n"),
          indent + 3);
      break;
    case SPP_CEEM_CHECK_EXTERNAL:
      IndentStatusMsg(
          status,
          T_("Check External Encryption Mode Status (CEEMS) : External\n"),
          indent + 3);
      break;
    case SPP_CEEM_CHECK_ENCR:
      IndentStatusMsg(
          status,
          T_("Check External Encryption Mode Status (CEEMS) : Encrypt\n"),
          indent + 3);
      break;
    default:
      break;
  }

  // See if VCELB is enabled.
  if (spd->VCELB) {
    IndentStatusMsg(
        status,
        T_("Volume Contains Encrypted Logical Blocks (VCELB): Enabled\n"),
        indent + 3);
  } else {
    IndentStatusMsg(
        status,
        T_("Volume Contains Encrypted Logical Blocks (VCELB): Disabled\n"),
        indent + 3);
  }

  // See what is providing the encryption keys.
  switch (spd->parametersControl) {
    case SPP_PARM_LOG_BLOCK_ENCR_NONE:
      IndentStatusMsg(status,
                      T_("Logical Block encryption parameters: No report\n"),
                      indent + 3);
      break;
    case SPP_PARM_LOG_BLOCK_ENCR_AME:
      IndentStatusMsg(
          status,
          T_("Logical Block encryption parameters: Application Managed\n"),
          indent + 3);
      break;
    case SPP_PARM_LOG_BLOCK_ENCR_DRIVE:
      IndentStatusMsg(
          status, T_("Logical Block encryption parameters: Drive Managed\n"),
          indent + 3);
      break;
    case SPP_PARM_LOG_BLOCK_LME_ADC:
      IndentStatusMsg(status,
                      T_("Logical Block encryption parameters: Library/Key "
                         "Management Appliance Managed\n"),
                      indent + 3);
      break;
    case SPP_PARM_LOG_BLOCK_UNSUP:
      IndentStatusMsg(status,
                      T_("Logical Block encryption parameters: Unsupported\n"),
                      indent + 3);
      break;
    default:
      break;
  }

  /* Only when both encryption and decryption are disabled skip the KAD Format
   * field. */
  if (spd->encryptionMode != SPP_ENCR_MODE_DISABLE
      && spd->decryptionMode != SPP_DECR_MODE_DISABLE) {
    switch (spd->kadFormat) {
      case SPP_KAD_KEY_FORMAT_NORMAL:
        IndentStatusMsg(
            status, T_("Key Associated Data (KAD) Descriptor: Normal key\n"),
            indent + 3);
        break;
      case SPP_KAD_KEY_FORMAT_REFERENCE:
        IndentStatusMsg(status,
                        T_("Key Associated Data (KAD) Descriptor: "
                           "Vendor-specific reference\n"),
                        indent + 3);
        break;
      case SPP_KAD_KEY_FORMAT_WRAPPED:
        IndentStatusMsg(
            status,
            T_("Key Associated Data (KAD) Descriptor: Wrapped public key\n"),
            indent + 3);
        break;
      case SPP_KAD_KEY_FORMAT_ESP_SCSI:
        IndentStatusMsg(
            status,
            T_("Key Associated Data (KAD) Descriptor: Key using ESP-SCSI\n"),
            indent + 3);
        break;
      default:
        break;
    }
  }

  return strlen(status);
}

/*
 * Request the encryption state of the next block
 * using a lowlevel SCSI interface.
 *
 * The device is send a:
 * - SPIN Security Protocol IN SCSI CDB. (0xA2)
 * - SPIN Get Data Encryption Status page. (0x21)
 *
 * The return data is interpreted and a status report is build.
 */
int GetScsiVolumeEncryptionStatus(int fd,
                                  const char* device_name,
                                  POOLMEM*& status,
                                  int indent)
{
  SPP_PAGE_BUFFER cmd_page{};
  auto cdb
      = BuildScsiSecurityCdb(SCSI_SPIN_OPCODE, SPIN_NEXT_BLOCK_ENCR_STATUS_PAGE,
                             static_cast<uint32_t>(sizeof(cmd_page)));

  // Retrieve the volume encryption status.
  if (!RecvScsiCmdPage(fd, device_name, &cdb, sizeof(cdb), &cmd_page,
                       sizeof(cmd_page))) {
    return 0;
  }

  /* We got a response which should contain a SPP_PAGE_NBES.
   * Create a pointer to the beginning of the generic
   * cmd_page structure. */
  SPP_PAGE_NBES* spnb = (SPP_PAGE_NBES*)&cmd_page;

  PmStrcpy(status, "");
  IndentStatusMsg(status, T_("Volume encryption status:\n"), indent);

  switch (spnb->compressionStatus) {
    case SPP_COMP_STATUS_UNKNOWN:
      IndentStatusMsg(status, T_("Compression Status: Unknown\n"), indent + 3);
      break;
    case SPP_COMP_STATUS_UNAVAIL:
      IndentStatusMsg(status, T_("Compression Status: Unavailable\n"),
                      indent + 3);
      break;
    case SPP_COMP_STATUS_ILLEGAL:
      IndentStatusMsg(status, T_("Compression Status: Illegal logical block\n"),
                      indent + 3);
      break;
    case SPP_COMP_STATUS_UNCOMPRESSED:
      IndentStatusMsg(status, T_("Compression Status: Compression Disabled\n"),
                      indent + 3);
      break;
    case SPP_COMP_STATUS_COMPRESSED:
      IndentStatusMsg(status, T_("Compression Status: Compression Enabled\n"),
                      indent + 3);
      break;
    default:
      break;
  }

  switch (spnb->encryptionStatus) {
    case SPP_ENCR_STATUS_UNKNOWN:
      IndentStatusMsg(status, T_("Encryption Status: Unknown\n"), indent + 3);
      break;
    case SPP_ENCR_STATUS_UNAVAIL:
      IndentStatusMsg(status, T_("Encryption Status: Unavailable\n"),
                      indent + 3);
      break;
    case SPP_ENCR_STATUS_ILLEGAL:
      IndentStatusMsg(status, T_("Encryption Status: Illegal logical block\n"),
                      indent + 3);
      break;
    case SPP_ENCR_STATUS_NOT_ENCRYPTED:
      IndentStatusMsg(status, T_("Encryption Status: Encryption Disabled\n"),
                      indent + 3);
      break;
    case SPP_ENCR_STATUS_ENCR_ALG_NOT_SUPP:
      IndentStatusMsg(status,
                      T_("Encryption Status: Encryption Enabled but with non "
                         "supported algorithm\n"),
                      indent + 3);
      break;
    case SPP_ENCR_STATUS_ENCRYPTED:
      IndentStatusMsg(status, T_("Encryption Status: Encryption Enabled\n"),
                      indent + 3);
      break;
    case SPP_ENCR_STATUS_ENCR_NOT_AVAIL:
      IndentStatusMsg(status,
                      T_("Encryption Status: Encryption Enabled but no valid "
                         "key available for decryption\n"),
                      indent + 3);
      break;
    default:
      break;
  }

  if (spnb->RDMDS) {
    IndentStatusMsg(
        status, T_("Raw Decryption Mode Disabled Status (RDMDS): Enabled\n"),
        indent + 3);
  } else {
    IndentStatusMsg(
        status, T_("Raw Decryption Mode Disabled Status (RDMDS): Disabled\n"),
        indent + 3);
  }

  if (spnb->EMES) {
    IndentStatusMsg(status,
                    T_("Encryption Mode External Status (EMES): Enabled\n"),
                    indent + 3);
  } else {
    IndentStatusMsg(status,
                    T_("Encryption Mode External Status (EMES): Disabled\n"),
                    indent + 3);
  }

  /* Only when the encryption status is set to SPP_ENCR_STATUS_ENCRYPTED we
   * can use the nextBlockKADFormat otherwise that value is bogus. */
  if (spnb->encryptionStatus == SPP_ENCR_STATUS_ENCRYPTED) {
    switch (spnb->nextBlockKADFormat) {
      case SPP_KAD_KEY_FORMAT_NORMAL:
        IndentStatusMsg(
            status,
            T_("Next Block Key Associated Data (KAD) Descriptor: Normal key\n"),
            indent + 3);
        break;
      case SPP_KAD_KEY_FORMAT_REFERENCE:
        IndentStatusMsg(status,
                        T_("Next Block Key Associated Data (KAD) Descriptor: "
                           "Vendor-specific reference\n"),
                        indent + 3);
        break;
      case SPP_KAD_KEY_FORMAT_WRAPPED:
        IndentStatusMsg(status,
                        T_("Next Block Key Associated Data (KAD) Descriptor: "
                           "Wrapped public key\n"),
                        indent + 3);
        break;
      case SPP_KAD_KEY_FORMAT_ESP_SCSI:
        IndentStatusMsg(status,
                        T_("Next Block Key Associated Data (KAD) Descriptor: "
                           "Key using ESP-SCSI\n"),
                        indent + 3);
        break;
      default:
        break;
    }
  }

  return strlen(status);
}

/*
 * See if we need a decryption key to read the next block
 * using a lowlevel SCSI interface.
 *
 * The device is send a:
 * - SPIN Security Protocol IN SCSI CDB. (0xA2)
 * - SPIN Get Data Encryption Status page. (0x21)
 */
bool NeedScsiCryptoKey(int fd, const char* device_name, bool use_drive_status)
{
  SPP_PAGE_BUFFER cmd_page{};
  const uint16_t page_code = use_drive_status
                                 ? SPIN_DATA_ENCR_STATUS_PAGE
                                 : SPIN_NEXT_BLOCK_ENCR_STATUS_PAGE;
  auto cdb = BuildScsiSecurityCdb(SCSI_SPIN_OPCODE, page_code,
                                  static_cast<uint32_t>(sizeof(cmd_page)));

  // Retrieve the volume encryption status.
  if (!RecvScsiCmdPage(fd, device_name, &cdb, sizeof(cdb), &cmd_page,
                       sizeof(cmd_page))) {
    return false;
  }

  if (use_drive_status) {
    /* We got a response which should contain a SPP_PAGE_DES.
     * Create a pointer to the beginning of the generic
     * cmd_page structure. */
    SPP_PAGE_DES* spd = (SPP_PAGE_DES*)&cmd_page;

    /* Return the status of the Volume Contains Encrypted Logical Blocks (VCELB)
     * field. */
    return (spd->VCELB) ? true : false;
  } else {
    /* We got a response which should contain a SPP_PAGE_NBES.
     * Create a pointer to the beginning of the generic
     * cmd_page structure. */
    SPP_PAGE_NBES* spnb = (SPP_PAGE_NBES*)&cmd_page;

    /* If the encryptionStatus is set to encrypted or encrypted but valid key
     * not available we know we need to load a key to decrypt the data. */
    switch (spnb->encryptionStatus) {
      case SPP_ENCR_STATUS_ENCRYPTED:
      case SPP_ENCR_STATUS_ENCR_NOT_AVAIL:
        return true;
      default:
        break;
    }
  }

  return false;
}

/*
 * See if encryption is enabled on a device using a lowlevel SCSI interface.
 *
 * The device is send a:
 * - SPIN Security Protocol IN SCSI CDB. (0xA2)
 * - SPIN Get Data Encryption Status page. (0x20)
 */
bool IsScsiEncryptionEnabled(int fd, const char* device_name)
{
  SPP_PAGE_BUFFER cmd_page{};
  auto cdb = BuildScsiSecurityCdb(SCSI_SPIN_OPCODE, SPIN_DATA_ENCR_STATUS_PAGE,
                                  static_cast<uint32_t>(sizeof(cmd_page)));

  // Retrieve the drive encryption status.
  if (!RecvScsiCmdPage(fd, device_name, &cdb, sizeof(cdb), &cmd_page,
                       sizeof(cmd_page))) {
    return false;
  }

  /* We got a response which should contain a SPP_PAGE_DES.
   * Create a pointer to the beginning of the generic
   * cmd_page structure. */
  SPP_PAGE_DES* spd = (SPP_PAGE_DES*)&cmd_page;

  /* When either encryptionMode or decryptionMode are not disabled we return
   * true */
  return (spd->encryptionMode != SPP_ENCR_MODE_DISABLE)
         || (spd->decryptionMode != SPP_DECR_MODE_DISABLE);
}

#else

bool ClearScsiEncryptionKey(int, const char*) { return false; }

bool SetScsiEncryptionKey(int, const char*, char*) { return false; }

int GetScsiDriveEncryptionStatus(int, const char*, POOLMEM*& status, int indent)
{
  PmStrcpy(status, "");
  IndentStatusMsg(status, T_("Drive encryption status: Unknown\n"), indent);
  return strlen(status);
}

int GetScsiVolumeEncryptionStatus(int,
                                  const char*,
                                  POOLMEM*& status,
                                  int indent)
{
  PmStrcpy(status, "");
  IndentStatusMsg(status, T_("Volume encryption status: Unknown\n"), indent);
  return strlen(status);
}

bool NeedScsiCryptoKey(int, const char*, bool) { return false; }

bool GetScsiEncryptionEnabled(int, const char*) { return false; }
#endif /* HAVE_LOWLEVEL_SCSI_INTERFACE */

static void IndentStatusMsg(POOLMEM*& status, const char* msg, int indent)
{
  int cnt;
  char indent_level[17];

  // See if we need to indent the line.
  if (indent > 0) {
    for (cnt = 0; cnt < indent && cnt < 16; cnt++) { indent_level[cnt] = ' '; }
    indent_level[cnt] = '\0';
    PmStrcat(status, indent_level);
  }

  PmStrcat(status, msg);
}
