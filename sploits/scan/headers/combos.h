#pragma once

typedef struct 
{
    char *username, *password;
    int username_len, password_len;
} Combo;

extern int cindex;
extern Combo *combos;

void combo_add(char *, char *);
void combos_init(void);
