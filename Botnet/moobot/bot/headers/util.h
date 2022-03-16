#pragma once

#include "includes.h"

BOOL util_send(int fd, const char *fmt, ...);
int util_strlen(char *);
BOOL util_strncmp(char *, char *, int);
BOOL util_strcmp(char *, char *);
int util_strcpy(char *, char *);
void util_memcpy(void *, void *, int);
void util_null(void *, char, int);
int util_atoi(char *, int);
char *util_itoa(int, int, char *);
int util_char_search(char *, int, char *, int);
int util_stristr(char *, int, char *);
ipv4_t util_get_local_address(void);
char *util_fdgets(char *, int, int);
char *util_strcat(char *, char *);
uint8_t util_strstr(char *, char *);
void util_sprintf(unsigned char *, char *, ...);
char util_isprint(unsigned char);
char *util_tokenize_string(char *, const char *);
ipv4_t choose_random_resolver(void);
void util_encryption(char str[]);
static inline int util_isupper(char);
static inline int util_isalpha(char);
static inline int util_isspace(char);
static inline int util_isdigit(char);
