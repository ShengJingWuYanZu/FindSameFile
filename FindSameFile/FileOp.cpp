#include "FileOp.h"
#include "md5.h"
#include <fstream>
#include <iostream>
#include <malloc.h>
#include <limits>
#include <sys/stat.h>
#ifdef WIN_API_MOD
#include <windows.h>
#include <fileapi.h>
#include <handleapi.h>
#endif

unsigned long long getfilesize(const char* dir)
{
	struct __stat64 st;
	__stat64(dir, &st);
	return st.st_size;
}

int calcFileMd5(const char* dir)
{
	if ((dir == NULL) || (strlen(dir) < 1))
	{
		return -1;
	}
	std::ifstream fd(dir, std::ios_base::in | std::ios_base::binary);
	if (!fd.is_open())
	{
		return -2;
	}
	unsigned long long filesize = getfilesize(dir);
	if (filesize > UINT_MAX)
	{
		std::cout << "************************MAXFILE:" << dir << ":" << filesize / 1024 / 1024 << "M" << std::endl;
	}
	else
	{
		char* buf = (char*)malloc(filesize + 512);
		memset(buf, 0x00, filesize + 512);
		int ireadtmp;
		if (buf)
		{
			unsigned long long readsize = 0;
			int irs = 200 * 1024 * 1024;
			while (readsize < filesize)
			{
				if (irs > filesize - readsize)
				{
					irs = filesize - readsize;
				}
				fd.read(buf + readsize, irs);
				ireadtmp = fd.gcount();
				if (ireadtmp > 0)
				{
					readsize += ireadtmp;
				}
			}
			//std::string str((std::istreambuf_iterator<char>(fd)), std::istreambuf_iterator<char>());
			//std::string md5(MD5(str).toStr());
			std::string md5(sha512(buf, readsize));
			std::cout << md5 << " size:" << filesize << std::endl;
			free(buf);
		}
	}
}

int WorkStart(const char* dir)
{
	int iRet = 0;
	char* cDirPath = NULL;
	do
	{
		if ((dir == NULL) || (strlen(dir) < 1))
		{
			iRet = -1;
			break;
		}
		cDirPath = (char*)malloc(MAX_DIR_PATH);
		if (cDirPath == NULL)
		{
			iRet = -2;
			break;
		}
		memset(cDirPath, 0x00, MAX_DIR_PATH);
		strcpy(cDirPath, dir);
#ifdef WIN_API_MOD
		strcat(cDirPath, "\\*");
		WIN32_FIND_DATA findFileData;
		HANDLE hFind = FindFirstFile(cDirPath, &findFileData);
		if (INVALID_HANDLE_VALUE != hFind)
		{
			do
			{
				if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (strcmp(".", findFileData.cFileName) == 0)
						;
					else if (strcmp("..", findFileData.cFileName) == 0)
						;
					else {
						memset(cDirPath, 0x00, MAX_DIR_PATH);
						strcpy(cDirPath, dir);
						strcat(cDirPath, "\\");
						strcat(cDirPath, findFileData.cFileName);
						std::cout << "===DIR===>" << cDirPath << std::endl;
						iRet = WorkStart(cDirPath);
						if (iRet != 0)
						{
							std::cout << "loop_WorkStart iRet:" << iRet << std::endl;
							iRet = -3;
							break;
						}
					}
				}
				else
				{
					memset(cDirPath, 0x00, MAX_DIR_PATH);
					strcpy(cDirPath, dir);
					strcat(cDirPath, "\\");
					strcat(cDirPath, findFileData.cFileName);
					std::cout << cDirPath << std::endl;
					{
						calcFileMd5(cDirPath);
					}

				}
			} while (FindNextFile(hFind, &findFileData) == TRUE);
		}
		else
		{
			if (GetLastError() == 5)
			{
				std::cout << "===DIR===>" << cDirPath << " 拒绝访问" << std::endl;
				iRet = 0;
			}
			else
			{
				std::cout << cDirPath << " 路径不存在" << std::endl;
				iRet = -4;
			}
		}
		FindClose(hFind);
#else
//LINUX TODO
#endif
	} while (0);
	if (cDirPath)
	{
		free(cDirPath);
		cDirPath = NULL;
	}
	return iRet;
}
