# define PACKED_16(l, r) (((uint16_t)(l) << 8) + (r))

# include <stdint.h>
# include <stdlib.h>
# include <string.h>

# include <stdio.h>

uint16_t getChecksum(uint8_t *packet) {
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
  return checksum;
}

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  uint16_t old_checksum = PACKED_16(packet[10], packet[11]);
  return getChecksum(packet) == old_checksum;
}

/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool forward(uint8_t *packet, size_t len) {
  if (!validateIPChecksum(packet, len)) {
    return false;
  }

  packet[8] -= 1;
  uint16_t checksum = getChecksum(packet);
  packet[10] = checksum >> 8;
  packet[11] = checksum & 0xff;
  return true;
}