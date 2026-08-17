#ifndef esphome_yield_H
#define esphome_yield_H

/* ESPHome ESP8266 port: WiFi and lwip only run when the sketch yields
   (cooperative CONT/SYS scheduling). A full scalar multiplication blocks
   for ~70-200 ms at 80 MHz, long enough for the WiFi RX queue to overflow
   and drop inbound frames, which stalls TCP handshakes on retransmission
   timeouts. The long loops call this every iteration; optimistic_yield
   rate-limits itself to at most one yield per interval_us of CONT time,
   so the cadence is ~1 ms regardless of loop cost, and a non-firing call
   is only a cycle-count read. The call sites do not depend on secret data. */
#if defined(ESP8266) || defined(ARDUINO_ARCH_ESP8266)
#ifdef __cplusplus
extern "C" void optimistic_yield(unsigned int interval_us);
#else
extern void optimistic_yield(unsigned int interval_us);
#endif
#define SODIUM_ESP8266_YIELD() optimistic_yield(1000u)
#else
#define SODIUM_ESP8266_YIELD() (void) 0
#endif

#endif
