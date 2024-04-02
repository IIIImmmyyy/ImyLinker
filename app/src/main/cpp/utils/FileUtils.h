//
// Created by Administrator on 2022/7/28.
//

#ifndef DUMPER_FILEUTILS_H
#define DUMPER_FILEUTILS_H

#include <string>

using namespace std;
class FileUtils {
public:
    static string GetStringFromFile(const string& path);
    static string GetStringFromFile2(const string& path);
    static string GetConfigJson(const string path);
    static void writeLog (string log);
};


#endif //DUMPER_FILEUTILS_H
