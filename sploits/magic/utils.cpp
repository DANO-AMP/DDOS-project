#include "utils.h"

std::vector<std::string> utils::split_buffer(const std::string& str, const std::string& delim)
{
    std::vector<std::string> tokens;
    std::string token;
    size_t prev = 0, pos = 0;

    do
    {
        pos = str.find(delim, prev);
        if(pos == std::string::npos)
        {
            pos = str.length();
        }

        token = str.substr(prev, pos-prev);

        if(!token.empty())
        {
            tokens.push_back(token);
        }

        prev = pos + delim.length();
    }
    while(pos < str.length() && prev < str.length());

    return tokens;
}