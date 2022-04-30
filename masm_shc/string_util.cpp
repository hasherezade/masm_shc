#include "string_util.h"

std::vector<std::string> split_by_delimiter(const std::string& line, char delim)
{
    std::string split;
    std::istringstream ss(line);
    std::vector<std::string> tokens;

    while (std::getline(ss, split, delim)) {
        split = trim(split);
        if (split.length() > 0) {
            tokens.push_back(split);
        }
    }
    return tokens;
}

size_t replace_char(std::string& str, const char from, const char to)
{
    size_t replaced = 0;
    for (size_t i = 0; i < str.length(); i++) {
        const char c = str[i];
        if (c == from) {
            str[i] = to;
            replaced++;
        }
    }
    return replaced;
}


void remove_prefix(std::string &str, const std::string &prefix)
{
    std::string::size_type i = str.find(prefix);

    if (i != std::string::npos)
        str.erase(i, prefix.length());
}

void replace_str(std::string &my_str, const std::string& from_str, const std::string& to_str)
{
    size_t index;
    while ((index = my_str.find(from_str)) != std::string::npos) {
        my_str.replace(index, from_str.length(), to_str);
    }
}
