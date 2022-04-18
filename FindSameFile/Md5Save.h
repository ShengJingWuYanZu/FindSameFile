#ifndef __MD5SAVE_H
#define __MD5SAVE_H

#include <map>

struct Md5SaveItm
{
public:
	char* dir;
	unsigned long long filesize;
	Md5SaveItm(const char*, const unsigned long long);
	~Md5SaveItm();
};

class Md5Save
{
private:
	std::map<char[64], Md5SaveItm*> mMd5Save;
public:
	Md5Save();
	~Md5Save();
	Md5SaveItm* insert(const char*, const Md5SaveItm&);
};

#endif
