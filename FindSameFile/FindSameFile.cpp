// FindSameFile.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
#include <iostream>
#include "FileOp.h"
using namespace std;

int main(int argc, char** argv)
{
	int iRet = 0;
	char dir[1024];
	do
	{
		if (argc == 1)
		{
			memset(dir, 0x00, 1024);
			cout << "请输入路径:";
			iRet = scanf("%s", dir);
			if (iRet != 1)
			{
				iRet = -1;
				cout << "输入错误" << endl;
				break;
			}
			cout << "输入的路径是:" << dir << endl;
		}
		else if (argc == 2)
		{

			if ((argv[1] == NULL) || (strlen(argv[1]) < 1))
			{
				iRet = -2;
				cout << "argv[1]参数错误" << endl;
				break;
			}
			memset(dir, 0x00, 1024);
			strcpy(dir, argv[1]);
		}
		else
		{
			iRet = -1;
			cout << "启动参数错误" << endl << argv[0] << " C:\\dirname" << endl;
			break;
		}
		int dirLen = strlen(dir);
		while (dirLen > 0)
		{
			dirLen = dirLen - 1;
			if (dir[dirLen] == '\\')
			{
				dir[dirLen] = '\0';
			}
			else
			{
				break;
			}
		}
		cout << "启动路径是:" << dir << endl;
		iRet = WorkStart(dir);
		if (iRet != 0)
		{
			cout << "WorkStart iRet:" << iRet << endl;
			iRet = -3;
			break;
		}
	} while (0);
	if (iRet == 0)
	{
		cout << "执行完成" << endl;
	}
	return iRet;
}
