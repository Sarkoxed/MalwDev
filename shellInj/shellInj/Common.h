#pragma once
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <winternl.h>
#include "resource.h"

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define err(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)
