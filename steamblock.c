/* Kill any game processes launched by Steam after a set daily play limit is reached */

#include <stdio.h>
#include <time.h>
#include <utime.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define CONFIG_FILE          "config.cfg"
#define TIME_FILE            ".time.bin"
#define DEFAULT_MINS         "120"

BOOL acquirePrivilegeByName(const TCHAR *szPrivilegeName)
{
	HANDLE htoken;
	TOKEN_PRIVILEGES tkp;
	DWORD dwerr;

	if (szPrivilegeName == NULL){
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, szPrivilegeName, &(tkp.Privileges[0].Luid))) return FALSE;

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &htoken)) return FALSE;

	if (!AdjustTokenPrivileges(htoken, FALSE, &tkp, 0, NULL, NULL) ||
	    GetLastError() != ERROR_SUCCESS){
		dwerr = GetLastError();
		CloseHandle(htoken);
		SetLastError(dwerr);
		return FALSE;
	}

	CloseHandle(htoken);
	SetLastError(ERROR_SUCCESS);

	return TRUE;
}

int IsProcessRunning(DWORD ParentID)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &pe32)){
		do{
			if(_tcsicmp(pe32.szExeFile, "steamwebhelper.exe") != 0 &&
			   _tcsicmp(pe32.szExeFile, "GameOverlayUI.exe")  != 0 &&
			    pe32.th32ParentProcessID == ParentID){
				printf("Process: %s\n", pe32.szExeFile);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);

	return 0;
}

int GetProcessID(const char *ProcessName)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &pe32)){
		do{
			if(_tcsicmp(pe32.szExeFile, ProcessName) == 0){
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);
	return -1;
}

void PrintTime(int ms)
{
	int hour, min, sec;
	int i;

	hour = min = sec = 0;

	sec = ms / 1000;
	if (sec > 59){
		min = sec / 60;
		sec = sec % 60;
	}
	if (min > 59){
		hour = min / 60;
		min = min % 60;
	}

	printf("%02d:%02d:%02d\n", hour, min, sec);
}

int KillProcess(int ProcessID)
{
	int ret;
	HANDLE explorer;
	explorer = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessID);
	ret = TerminateProcess(explorer, 1);
	CloseHandle(explorer);
	return ret;
}

void WriteDefaultTime()
{
	FILE *fp;
	char *str;

	fp = fopen(CONFIG_FILE, "w");
	str = malloc(sizeof(char)*50);
	strcpy(str, "MinsPerDay=");
	strcat(str, DEFAULT_MINS);
	if (fwrite(str, strlen(str), 1, fp) == 0) printf("write err\n");
	free(str);
	fclose(fp);
}

int GetTimeInitial()
{
	FILE *fp;
	char c[] = "MinsPerDay=";
	char buf[100];
	char ms[100];
	int ret;

	if ((fp = fopen(CONFIG_FILE, "r")) == NULL){
		fclose(fp);
		WriteDefaultTime();
		return atoi(DEFAULT_MINS)*60*1000;
	}

	fread(buf, strlen(c), 1, fp);

	memset(ms, 0, 100);
	while(1){
		memset(buf, 0, 100);
		if (fread(buf, 1, 1, fp) == EOF) break;
		if (buf[0] == '\n' || buf[0] == '\0') break;
		strncat(ms, buf, 1);
	}

	ret = atoi(ms);
	if (strlen(ms) == 0 || ret == 0){
		fclose(fp);
		WriteDefaultTime();
		return atoi(DEFAULT_MINS)*60*1000;
	}

	fclose(fp);
	return ret*60*1000;
}

void WriteTimeRemaining(int *ms)
{
	FILE *fp = fopen(TIME_FILE, "wb");
	struct stat config, time;
	time_t mtime_config, mtime_time;

	stat(CONFIG_FILE, &config);
	stat(TIME_FILE,   &time);
	if (config.st_mtime >= time.st_mtime){
		*ms = GetTimeInitial();
	}

	Sleep(100);

	fwrite(&(*ms), 1, sizeof(int), fp);
	fclose(fp);
}

int GetTimeRemaining()
{
	FILE *fp = fopen(TIME_FILE, "rb+");
	int data;
	int ret;

	if (!fp){
		open(TIME_FILE, O_CREAT);
	}

	ret = fread(&data, sizeof(int), 1, fp);
	if (ret == 0){
		data = GetTimeInitial();
		WriteTimeRemaining(&data);
	}

	fclose(fp);
	return data;
}

int main(int argc, char** argv)
{
	char *ProcessName;
	DWORD ProcessID = -1;
	int ret;
	int time;
	int ms;

	time = GetTimeRemaining();
	ms = time;

	ProcessName = "steam.exe";
	do{
		ProcessID = GetProcessID(ProcessName);
		Sleep(1000);
	} while (ProcessID == -1);

	printf("%s ID: %d\n", ProcessName, ProcessID);

	PrintTime(ms);
	while (TRUE){
		ret = IsProcessRunning(ProcessID);
		WriteTimeRemaining(&ms);
		Sleep(900);
		if (ret){
			PrintTime(ms);
			ms -= 1000;
		}
		if (ms <= 0){
			ms = 0;
			ret = KillProcess(ret);
		}
	}

	return 0;
}
