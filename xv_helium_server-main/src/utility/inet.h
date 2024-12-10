/**
 * @file inet.h
 * @brief Platform specific network includes
 */

#ifndef INET_H
#define INET_H

#ifdef _WIN32
#include <Winsock2.h>
#else
#include <arpa/inet.h>
#endif  // _WIN32

#endif  // INET_H
