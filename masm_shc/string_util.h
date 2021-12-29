#pragma once

#include <Windows.h>
#include <iostream>

#include <sstream>
#include <string>

#include <vector>
#include <map>

#include <iomanip>

inline std::string& trim(std::string& s)
{
    const char* t = " \t\n\r\f\v";
    s.erase(s.find_last_not_of(t) + 1);
    s.erase(0, s.find_first_not_of(t));
    return s;
}

std::vector<std::string> split_by_delimiter(const std::string& line, char delim);

size_t replace_char(std::string &str, const char from, const char to);

void remove_prefix(std::string &str, const std::string &prefix);

void replace_str(std::string &my_str, const std::string& from_str, const std::string& to_str);
