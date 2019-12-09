# define PACKED_16(a, b) (((uint16_t)(a) << 8) + (b))

# include "rip.h"

# include <stdio.h>
# include <stdint.h>
# include <stdlib.h>
# include <string.h>
# include <arpa/inet.h>

bool validateMask(uint32_t mask) {
  bool status = 0;
  for (int i = 0; i < 32; ++ i, mask >>= 1) {
    if (status == 0) {
      status ^= mask & 1;
    } else if (!(mask & 1)) {
      return false;
    }
  }
  return true;
}

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  output -> numEntries = 0;

  uint16_t ihl = (packet[0] & 0xf) << 2;
  uint16_t total_length = PACKED_16(packet[2], packet[3]);
  uint16_t rip_start = ihl + 8, num_entries = (len - rip_start) / 20; // + UDP header
  uint8_t command = packet[rip_start], version = packet[rip_start + 1];
  uint16_t zero = PACKED_16(packet[rip_start + 2], packet[rip_start + 3]);
  if (total_length != len || (command != 1 && command != 2) || version != 2 || zero != 0) {
    return false;
  }

  output -> command = command;
  uint32_t *entries = (uint32_t *) (&packet[rip_start + 4]);
  for (uint16_t i = 0; i < num_entries; ++ i) {
    uint32_t *entry = entries + 5 * i;
    uint16_t family = PACKED_16(entry[0] & 0xff, (entry[0] >> 8) & 0xff);
    uint16_t tag = PACKED_16((entry[0] >> 16) & 0xff, (entry[0] >> 24) & 0xff);
    uint32_t mask = htonl(entry[2]), metric = htonl(entry[4]);
    // printf("%d %d %d %d %x %d\n", command, family, tag, metric, mask, validateMask(mask));
    if ((command == 1 && family != 0) || (command == 2 && family != 2) || tag != 0 || (metric < 1 || metric > 16) || !validateMask(mask)) {
      return false;
    }
    memcpy(&(output -> entries[output -> numEntries ++]), &entry[1], 16);
  }

  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  buffer[0] = rip -> command, buffer[1] = 2, buffer[2] = buffer[3] = 0;
  for (uint16_t i = 0; i < rip -> numEntries; ++ i) {
    uint8_t *entry = buffer + 4 + 20 * i;
    entry[0] = 0, entry[1] = (rip -> command == 1) ? 0 : 2, entry[2] = entry[3] = 0;
    memcpy(entry + 4, &(rip -> entries[i]), 16);
  }
  return 4 + 20 * rip -> numEntries;
}