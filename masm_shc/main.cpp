#include <Windows.h>
#include <iostream>

#include <fstream>
#include <sstream>
#include <string>
#include <iostream>

#include <vector>
#include <map>

bool g_is32bit = false;

typedef struct {
    std::string infile;
    std::string outfile;

    bool inlineStrings;
    bool removeCRT;
    bool appendRSPStub;
} t_params;

bool is_empty(std::string &str)
{
    for (size_t i = 0; i < str.length(); i++) {
        const char c = str[i];
        if (!isspace(c)) {
            return false;
        }
    }
    return true;
}

std::string replace_char(std::string str, const char to_replace[], const size_t to_replace_count)
{
    for (size_t i = 0; i < str.length(); i++) {
        const char c = str[i];
        for (size_t k = 0; k < to_replace_count; k++) {
            if (c == to_replace[k]) str[i] = ' ';
        }
    }
    return str;
}

bool has_token(std::vector<std::string> &tokens, const std::string &token)
{
    std::vector<std::string>::iterator itr;
    for (itr = tokens.begin(); itr != tokens.end(); itr++) {
        if (*itr == token) {
            return true;
        }
    }
    return false;
}

std::string get_constant(std::map<std::string, std::string> &consts_lines, std::vector<std::string> &tokens_line)
{
    std::map<std::string, std::string>::iterator itr;
    for (itr = consts_lines.begin(); itr != consts_lines.end(); itr++) {
        std::string const_name = itr->first;
        if (has_token(tokens_line, const_name)) {
            return const_name;
        }
    }
    return "";
}

void remove_prefix(std::string &str, const std::string &prefix)
{
    std::string::size_type i = str.find(prefix);

    if (i != std::string::npos)
        str.erase(i, prefix.length());
}

void replace_str(std::string &my_str, const std::string from_str, const std::string to_str)
{
    int index;

    while ((index = my_str.find(from_str)) != std::string::npos) {
        my_str.replace(index, from_str.length(), to_str);
    }
}

std::vector<std::string> split_to_tokens(std::string orig_line)
{
    const char to_replace[] = { '\t', ',' };

    std::string line = replace_char(orig_line, to_replace, _countof(to_replace));

    std::string split;
    std::istringstream ss(line);
    std::vector<std::string> tokens;

    while (std::getline(ss, split, ' ')) {

        remove_prefix(split, "FLAT:");

        if (!is_empty(split)) {
            tokens.push_back(split);
        }
    }
    return tokens;
}

void append_align_rsp(std::ofstream &ofile)
{
    char stub[] = "PUBLIC  AlignRSP\n"
        "_TEXT SEGMENT\n"
        "	; AlignRSP - by @mattifestation (http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html)\n"
        "	; AlignRSP is a simple call stub that ensures that the stack is 16 - byte aligned prior\n"
        "	; to calling the entry point of the payload.This is necessary because 64 - bit functions\n"
        "	; in Windows assume that they were called with 16 - byte stack alignment.When amd64\n"
        "	; shellcode is executed, you can't be assured that you stack is 16-byte aligned. For example,\n"
        "	; if your shellcode lands with 8 - byte stack alignment, any call to a Win32 function will likely\n"
        "	; crash upon calling any ASM instruction that utilizes XMM registers(which require 16 - byte)\n"
        "	; alignment.\n\n"
        "	AlignRSP PROC\n"
        "	push rsi; Preserve RSI since we're stomping on it\n"
        "	mov  rsi, rsp; Save the value of RSP so it can be restored\n"
        "	and  rsp, 0FFFFFFFFFFFFFFF0h; Align RSP to 16 bytes\n"
        "	sub  rsp, 020h; Allocate homing space for ExecutePayload\n"
        "	call main; Call the entry point of the payload\n"
        "	mov  rsp, rsi; Restore the original value of RSP\n"
        "	pop  rsi; Restore RSI\n"
        "	ret; Return to caller\n"
        "	AlignRSP ENDP\n"
        "_TEXT ENDS\n\n";

    ofile << stub;
}

void process_file(t_params &params)
{
    std::ifstream file(params.infile);
    if (!file.is_open()) {
        return;
    }

    std::ofstream ofile(params.outfile);
    if (!ofile.is_open()) {
        return;
    }
    std::map<std::string, std::string> consts_lines;

    std::string seg_name = "";
    std::string const_name = "";
    bool code_start = false;

    std::string line;
    for (size_t line_count = 0; std::getline(file, line); line_count++) {

        std::vector<std::string> tokens = split_to_tokens(line);

        if (tokens.size() == 0) {
            ofile << line << "\n"; //copy empty line
            continue;
        }
        if (tokens[0] == ".686P") {
            g_is32bit = true;
        }

        if (tokens[0] == "EXTRN") {
            std::cerr << "[ERROR] Line " << std::dec << line_count << ": External dependency detected:\n" << line << "\n";
        }

        bool in_skipped = false;
        bool in_const = false;

        if (tokens.size() >= 2) {
            if (tokens[1] == "SEGMENT") {
                seg_name = tokens[0];
                if (!code_start && seg_name == "_TEXT") {
                    code_start = true;
                    if (g_is32bit) {
                        ofile << "assume fs:nothing\n";
                    }
                    else if (params.appendRSPStub) {
                        append_align_rsp(ofile);
                        std::cerr << "[INFO] Entry Point: AlignRSP\n";
                    }

                }
                if (seg_name == "_BSS") {
                    std::cerr << "[ERROR] Line " << std::dec << line_count << ": _BSS segment detected! Remove all global and static variables!\n";
                }
            }

            if (seg_name == "pdata" || seg_name == "xdata") {
                in_skipped = true;
            }
            if (seg_name == "CONST") {
                in_const = true;
            }
            if (tokens[1] == "ENDS" && tokens[0] == seg_name) {
                seg_name = "";

                if (in_const) continue; // skip the ending of the section
            }
        }
        if (in_skipped) {
            continue;
        }
        if (params.removeCRT && tokens[0] == "INCLUDELIB") {
            if (tokens[1] == "LIBCMT" || tokens[1] == "OLDNAMES") {
                ofile << "; " << line << "\n"; //copy commented out line
                continue;
            }
            std::cerr << "[ERROR] Line " << std::dec << line_count << ": INCLUDELIB detected! Remove all external dependencies!\n";
        }
        if (params.inlineStrings && in_const) {
            if (tokens[1] == "DB") {
                const_name = tokens[0];
                //ofile << ";Token name: " << const_name << "\n";
            }
            if (const_name != "") {
                if (consts_lines.find(const_name) == consts_lines.end()) {
                    consts_lines[const_name] = line;
                }
                else {
                    consts_lines[const_name] += "\n" + line;
                }
            }
            continue;
        }
        std::string curr_const = get_constant(consts_lines, tokens);
        if (params.inlineStrings && curr_const != "") {
            //ofile << ";Token found: " << const_name << "\n";
            std::string label_after = "after_" + curr_const;
            ofile << "\tCALL " << label_after << "\n";
            ofile << consts_lines[curr_const] << "\n";
            ofile << label_after << ":\n";
            if (tokens.size() > 2 && (tokens[0] == "lea" || tokens[0] == "mov")) {
                std::string reg = tokens[1];
                ofile << "\tPOP  " << reg << "\n";
            }
            ofile << "\n";
            ofile << "; " << line << "\n"; //copy commented out line
            continue;
        }
        if (!g_is32bit && has_token(tokens, "gs:96")) {
            replace_str(line, "gs:96", "gs:[96]");
        }

        ofile << line << "\n"; //copy line
    }
    file.close();
    ofile.close();

    if (params.inlineStrings) {
        std::cerr << "[INFO] Strings have been inlined. It may require to change some short jumps (jmp SHORT) into jumps (jmp)\n";
    }
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        std::cout << "Args: <input: MASM file> <output file>\n";
        return 1;
    }

    t_params params;
    params.appendRSPStub = true;
    params.inlineStrings = true;
    params.removeCRT = true;

    params.infile = argv[1];
    params.outfile = argv[2];

    process_file(params);
    return 0;
}
