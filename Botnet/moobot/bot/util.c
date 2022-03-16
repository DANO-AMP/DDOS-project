#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "headers/includes.h"
#include "headers/util.h"
#include "headers/entry.h"
#include "headers/rand.h"

void util_encryption(char str[]) {
    int i = 0;

    while(str[i]) {
        str[i] = str[i] - 5;
        ++i;
    }

    str[i] = '\0';
}

BOOL util_send(int fd, const char *fmt, ...)
{
    char buffer[2048 + 2];
    va_list args;
    int len;
    va_start(args, fmt);
    len = vsnprintf(buffer, 2048, fmt, args);
    va_end(args);
    if(len > 0)
    {
        if(len > 2048)
        {
            len = 2048;
        }
        if(send(fd, buffer, len, MSG_NOSIGNAL) != len)
        {
            return FALSE;
        }
    }
    return TRUE;
}


int util_strlen(char *str)
{
    int c = 0;

    while(*str++ != 0)
    {
        c++;
    }

    return c;
}

char *util_strcat(char *dest, char *src)
{
    char *rdest = dest;

    while(*dest) dest++;
    while(*dest++ = *src++);

    return rdest;
}

uint8_t util_strstr(char *string, char *sub_string)
{
    char *a, *b;

    b = sub_string;

    if(*b == 0)
    {
        return TRUE;
    }

    for(; *string != 0; string += 1)
    {
        if(*string != *b)
        {
            continue;
        }

        a = string;

        while(TRUE)
        {
            if(*b == 0)
            {
                return TRUE;
            }
            if(*a++ != *b++)
            {
                break;
            }
        }

        b = sub_string;
    }

    return FALSE;
}

static void print_char(unsigned char **str, int c)
{
    if(str)
    {
        **str = c;
        ++(*str);
    }
    else
    {
        (void)write(1, &c, 1);
    }
}

static int prints(unsigned char **out, const unsigned char *string, int width, int pad)
{
    register int pc = 0, padchar = ' ';

    if(width > 0)
    {
        register int len = 0;
        register const unsigned char *ptr;
        for(ptr = string; *ptr; ++ptr) ++len;
        if(len >= width) width = 0;
        else width -= len;
        if(pad & 2)
        {
            padchar = '0';
        }
    }
    
    if(!(pad & 1))
    {
        for(; width > 0; --width)
        {
            print_char(out, padchar);
            ++pc;
        }
    }

    for(; *string ; ++string)
    {
        print_char(out, *string);
        ++pc;
    }

    for(; width > 0; --width)
    {
        print_char(out, padchar);
        ++pc;
    }

    return pc;
}

static int print_i(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
    unsigned char print_buf[12];
    register unsigned char *s;
    register int t = 0, neg = 0, pc = 0;
    register unsigned int u = i;

    if(i == 0)
    {
        print_buf[0] = '0';
        print_buf[1] = '\0';
        return prints(out, print_buf, width, pad);
    }

    if(sg && b == 10 && i < 0)
    {
        neg = 1;
        u = -i;
    }

    s = print_buf + 12 - 1;
    *s = '\0';

    while(u)
    {
        t = u % b;
        if(t >= 10)
        {
            t += letbase - '0' - 10;
        }
        *--s = t + '0';
        u /= b;
    }

    if(neg)
    {
        if(width && (pad & 2))
        {
            print_char(out, '-');
            ++pc;
            --width;
        }
        else
        {
            *--s = '-';
        }
    }

    return pc + prints(out, s, width, pad);
}

static int print(unsigned char **out, const unsigned char *format, va_list args)
{
    register int width, pad;
    register int pc = 0;
    unsigned char scr[2];

    for(; *format != 0; ++format)
    {
        if(*format == '%')
        {
            ++format;
            width = pad = 0;
            if(*format == '\0')
            {
            	break;
            }
            if(*format == '%')
            {
            	goto out;
            }
            if(*format == '-')
            {
                ++format;
                pad = 1;
            }
            while(*format == '0')
            {
                ++format;
                pad |= 2;
            }
            for(; *format >= '0' && *format <= '9'; ++format)
            {
                width *= 10;
                width += *format - '0';
            }
            if(*format == 's')
            {
                register char *s = (char *)va_arg( args, intptr_t );
                pc += prints(out, s?s:NULL, width, pad);
                continue;
            }
            if(*format == 'd')
            {
                pc += print_i(out, va_arg(args, int), 10, 1, width, pad, 'a');
                continue;
            }
            if(*format == 'x')
            {
                pc += print_i(out, va_arg(args, int), 16, 0, width, pad, 'a');
                continue;
            }
            if(*format == 'X')
            {
                pc += print_i(out, va_arg(args, int), 16, 0, width, pad, 'A');
                continue;
            }
            if(*format == 'u')
            {
                pc += print_i(out, va_arg(args, int), 10, 0, width, pad, 'a');
                continue;
            }
            if(*format == 'c')
            {
                scr[0] = (unsigned char)va_arg( args, int);
                scr[1] = '\0';
                pc += prints(out, scr, width, pad);
                continue;
            }
        }
        else
        {
			out:
            print_char(out, *format);
            ++pc;
        }
    }

    if(out)
    {
        **out = '\0';
    }
    
    va_end(args);

    return pc;
}

void util_sprintf(unsigned char *s, char *string, ...)
{
    va_list arg;
    va_start(arg, string);
    print(&s, string, arg);
    va_end(arg);
}

BOOL util_strncmp(char *str1, char *str2, int len)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if(l1 < len || l2 < len)
    {
        return FALSE;
    }

    while(len--)
    {
        if(*str1++ != *str2++)
        {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL util_strcmp(char *str1, char *str2)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if(l1 != l2)
    {
        return FALSE;
    }

    while(l1--)
    {
        if(*str1++ != *str2++)
        {
            return FALSE;
        }
    }

    return TRUE;
}

int util_strcpy(char *dst, char *src)
{
    int l = util_strlen(src);

    util_memcpy(dst, src, l + 1);

    return l;
}

void util_memcpy(void *dst, void *src, int len)
{
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while(len--)
    {
        *r_dst++ = *r_src++;
    }
}

char util_isprint(unsigned char c)
{
    if(c >= 0x20 && c <= 0x7e)
    {
        return TRUE;
    }

    return FALSE;
}

void util_null(void *buf, char c, int len)
{
    char *zero = buf;
    while(len--)
    {
        *zero++ = c;
    }
}

char *util_tokenize_string(char *str, const char *delim)
{
    static char *static_str = 0;
    int index = 0;
    int str_len = 0;
    int found = 0;

    if(delim == 0 || (str == 0 && static_str == 0))
    {
        return 0;
    }

    if(str == 0)
    {
        str = static_str;
    }

    while(str[str_len])
    {
        str_len++;
    }

    for(index = 0; index < str_len; index++)
    {
        if(str[index] == delim[0])
        {
            found = 1;
            break;
        }
    }

    if(!found)
    {
        static_str = 0;
        return str;
    }

    if(str[0] == delim[0])
    {
        static_str = (str + 1);
        return (char *)delim;
    }

    str[index] = '\0';

    if((str + index + 1) != 0)
    {
        static_str = (str + index + 1);
    }
    else
    {
        static_str = 0;
    }

    return str;
}

int util_atoi(char *str, int base)
{
	unsigned long acc = 0;
	int c = 0;
	unsigned long cutoff;
	int neg = 0, any = 0, cutlim = 0;

	do
    {
		c = *str++;
	}
    while(util_isspace(c));
	
    if(c == '-')
    {
		neg = 1;
		c = *str++;
	}
    else if(c == '+')
    {
		c = *str++;
    }

	cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
	cutlim = cutoff % (unsigned long)base;
	cutoff /= (unsigned long)base;
	for(acc = 0, any = 0;; c = *str++)
    {
		if(util_isdigit(c))
		{
			c -= '0';
		}
		else if(util_isalpha(c))
		{
			c -= util_isupper(c) ? 'A' - 10 : 'a' - 10;
		}
		else
		{
			break;
		}

		if(c >= base)
		{
			break;
		}

		if(any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
		{
			any = -1;
		}
		else
        {
			any = 1;
			acc *= base;
			acc += c;
		}
	}

	if(any < 0)
    {
		acc = neg ? LONG_MIN : LONG_MAX;
	}
    else if(neg)
    {
		acc = -acc;
    }

    return (acc);
}

char *util_itoa(int value, int radix, char *string)
{
    if(string == NULL)
    {
        return NULL;
    }

    if(value != 0)
    {
        char scratch[34];
        int neg = 0;
        int offset = 0;
        int c = 0;
        unsigned int accum = 0;

        offset = 32;
        scratch[33] = 0;

        if(radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }

        while(accum)
        {
            c = accum % radix;
            if(c < 10)
            {
                c += '0';
            }
            else
            {
                c += 'A' - 10;
            }

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }
        
        if(neg)
        {
            scratch[offset] = '-';
        }
        else
        {
            offset++;
        }

        util_strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}

int util_char_search(char *buf, int buf_len, char *mem, int mem_len)
{
    int i = 0;
    int matched = 0;

    if(mem_len > buf_len)
    {
        return -1;
    }

    for(i = 0; i < buf_len; i++)
    {
        if(buf[i] == mem[matched])
        {
            if(++matched == mem_len)
            {
                return i + 1;
            }
        }
        else
        {
            matched = 0;
        }
    }

    return -1;
}

int util_stristr(char *haystack, int haystack_len, char *str)
{
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while(haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if(a == b)
        {
            if(++match_count == str_len)
            {
                return (ptr - haystack);
            }
        }
        else
        {
            match_count = 0;
        }
    }

    return -1;
}

ipv4_t choose_random_resolver(void)
{
    switch(rand_new() % 4)
    {
        case 0:
        {
            return INET_ADDR(8,8,8,8);
        }
        case 1:
        {
            return INET_ADDR(8,8,4,4);
        }
        /*
        case 2:
        {
            return INET_ADDR(4,2,2,2);
        }
        case 3:
        {
            return INET_ADDR(4,2,2,4);
        }
        */
        case 2:
        {
            return INET_ADDR(173,245,58,152);
        }
        case 3:
        {
            return INET_ADDR(173,245,59,188);
        }
    }
}

ipv4_t util_get_local_address(void)
{
    int sock = 0;
    struct sockaddr_in dest_addr;
    socklen_t len = sizeof(dest_addr);

    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        return FALSE;
    }

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = choose_random_resolver();
    dest_addr.sin_port = htons(53);

    errno = 0;
    connect(sock, (struct sockaddr_in *)&dest_addr, sizeof(dest_addr));

    getsockname(sock, (struct sockaddr_in *)&dest_addr, &len);

    close(sock);

    return dest_addr.sin_addr.s_addr;
}

char *util_fdgets(char *buffer, int buffer_size, int fd)
{
    int got = 0, total = 0;
    do
    {
        got = read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    }
    while(got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');

    return total == 0 ? NULL : buffer;
}

static inline int util_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

static inline int util_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

static inline int util_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

static inline int util_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}
