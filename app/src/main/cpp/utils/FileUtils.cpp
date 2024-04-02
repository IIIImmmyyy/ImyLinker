//
// Created by Administrator on 2022/7/28.
//

#define LOG false
#include "FileUtils.h"
#include <sstream>
#include <fstream>


string FileUtils::GetStringFromFile(const string& path) {
    ifstream  file(path,ios::in);
    string temp;
    if (!file.is_open()){
        return std::string();
    }
    string res;
    while (getline(file,temp)){
        res+=temp;
        res+='\n';
    }
    file.close();
    return res;
}

void FileUtils::writeLog(string log) {
#if(LOG)
    FILE *pFile = fopen("/data/data/com.tencent.lolm/files/imy.log", "a");
    if (pFile!= nullptr){
        //写上时间
        struct timeval now_time;
        gettimeofday(&now_time, NULL);
        time_t tt = now_time.tv_sec;
        tm *temp = localtime(&tt);
        char time_str[32]={NULL};
        sprintf(time_str,"%04d-%02d-%02d%02d:%02d:%02d",temp->tm_year+ 1900,temp->tm_mon+1,temp->tm_mday,temp->tm_hour,temp->tm_min, temp->tm_sec);
        fputs(time_str,pFile);
        fputs(":",pFile);
        fputs(log.c_str(), pFile);
        fputs("\n",pFile);
        fclose(pFile);
    }
#endif
}

string FileUtils::GetConfigJson(const string path) {
    const string &basicString = GetStringFromFile2(path);
    //解密
//    char *decrypt = Rc4Decrypt(basicString.c_str(), "85ba2d23894a6dde0850c7a515fabcde");
    return basicString.c_str();
}

string FileUtils::GetStringFromFile2(const string &path) {
    ifstream  file(path,ios::in);
    string temp;
    if (!file.is_open()){
        return std::string();
    }
    string res;
    while (getline(file,temp)){
        res+=temp;
    }
    file.close();
    return res;
}
