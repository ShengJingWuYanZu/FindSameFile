#include "Md5Save.h"
#include <iostream>
#include <malloc.h>

Md5SaveItm::Md5SaveItm(const char* diri, const unsigned long long sizei)
{
	int dirsize = strlen(diri) + 1;
	Md5SaveItm::dir = (char*)malloc(dirsize);
	if (Md5SaveItm::dir != NULL)
	{
		strcpy(Md5SaveItm::dir, diri);
		Md5SaveItm::filesize = sizei;
	}
	else
	{
		Md5SaveItm::filesize = 0;
	}
}

Md5SaveItm::~Md5SaveItm()
{
	if (Md5SaveItm::dir != NULL)
	{
		free(Md5SaveItm::dir);
		Md5SaveItm::dir = NULL;
	}
}

Md5SaveItm* Md5Save::insert(const char* pMd5, const Md5SaveItm& itm)
{
	if (pMd5 == NULL)
	{
		return NULL;
	}
}
