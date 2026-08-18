/*
 * goodbyedpi.h — Common definitions for Linux port.
 *
 * Port of the Windows goodbyedpi.h.
 * WinDivert types removed; TRUE/FALSE and debug kept.
 */
#ifndef _GOODBYEDPI_H
#define _GOODBYEDPI_H

#include <stdio.h>

#define HOST_MAXLEN 253
#define MAX_PACKET_SIZE 9016

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#ifndef DEBUG
#define debug(...) do {} while (0)
#else
#define debug(...) printf(__VA_ARGS__)
#endif

#endif /* _GOODBYEDPI_H */
