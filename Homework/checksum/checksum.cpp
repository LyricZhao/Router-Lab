# define PACKED_16(l, r) (((uint16_t)(l) << 8) + (r))

# include <stdint.h>
# include <stdlib.h>
# include <string.h>

# include <stdio.h>

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  uint16_t old_checksum = PACKED_16(packet[10], packet[11]);

  uint8_t ihl = (packet[0] & 0xf) << 2;
  uint32_t checksum = 0;
  for (uint8_t i = 0; i < ihl; i += 2) {
    if (i == 10) continue;
    checksum += PACKED_16(packet[i], packet[i + 1]);
  }
  while (checksum >> 16) {
    checksum = (checksum >> 16) + (checksum & 0xffff);
  }
  checksum = 0xffff ^ checksum;
  return checksum == old_checksum;
}