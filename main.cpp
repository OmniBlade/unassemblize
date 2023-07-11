/**
 * @file
 *
 * @brief main function and option handling.
 *
 * @copyright Assemblize is free software: you can redistribute it and/or
 *            modify it under the terms of the GNU General Public License
 *            as published by the Free Software Foundation, either version
 *            3 of the License, or (at your option) any later version.
 *            A full copy of the GNU General Public License can be found in
 *            LICENSE
 */
#include "function.h"
#include "gitinfo.h"
#include <LIEF/LIEF.hpp>
#include <stdio.h>
#include <inttypes.h>
#include <getopt.h>

void print_help()
{
    char revision[12] = { 0 };
    const char* version = GitTag[0] == 'v' ? GitTag : GitShortSHA1;

    if (GitTag[0] != 'v') {
        snprintf(revision, sizeof(revision), "r%d ", GitRevision);
    }

    printf(
        "\nunassemblize %s%s%s\n"
        "    x86 Unassembly tool\n\n"
        "Usage:\n"
        "  unassemblize [OPTIONS] [INPUT]\n"
        "Options:\n"
        "  -o --output     Filename for single file output.\n"
        "  -f --format     Assembly output format.\n"
        "  -m --manifest   Configuration file describing how to dissassemble the input\n"
        "                  file.\n"
        "  -s --start      Starting address of a single function to dissassemble in\n"
        "                  hexidecimal notation.\n"
        "  -e --end        Ending address of a single function to dissassemble in\n"
        "                  hexidecimal notation.\n"
        "  -n --nametable  File containing address to symbols mappings.\n"
        "  --section       Section to target for dissassembly, defaults to '.text'.\n"
        "  -h --help       Displays this help.\n\n",
        revision,
        GitUncommittedChanges ? "~" : "",
        version);
}

int main(int argc, char **argv)
{
    if (argc <= 1) {
        print_help();
        return -1;
    }

    const char* section_name = ".text";
    const char* output = nullptr;
    const char* name_file = nullptr;
    const char* manifest_file = nullptr;
    const char* format_string = nullptr;
    uint64_t start_addr = 0;
    uint64_t end_addr = 0;

    while (true) {
        static struct option long_options[] = {
            {"output", required_argument, nullptr, 'o'},
            {"format", required_argument, nullptr, 'f'},
            {"start", required_argument, nullptr, 's'},
            {"end", required_argument, nullptr, 'e'},
            {"nametable", required_argument, nullptr, 'n'},
            {"manifest", required_argument, nullptr, 'm'},
            {"section", required_argument, nullptr, 1},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, no_argument, nullptr, 0},
        };

        int option_index = 0;

        int c = getopt_long(argc, argv, "+h?o:f:s:e:n:f:m:", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 1:
            section_name = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        case 'f':
            format_string = optarg;
            break;
        case 's':
            start_addr = strtoull(optarg, nullptr, 16);
            break;
        case 'e':
            end_addr = strtoull(optarg, nullptr, 16);
            break;
        case 'n':
            name_file = optarg;
            break;
        case 'm':
            manifest_file = optarg;
            break;
        case '?':
            printf("\nOption %d not recognised.\n", optopt);
            print_help();
            return 0;
        case ':':
            printf("\nAn option is missing arguments.\n");
            print_help();
            return 0;
        case 'h':
            print_help();
            break;
        default:
            break;
        }
    }

    unassemblize::Executable exe(argv[optind]);
    unassemblize::Function func(exe, section_name, start_addr, end_addr);

    if (start_addr != 0 && end_addr != 0) {
        func.disassemble();
        printf("%s", func.dissassembly().c_str());
    }

    return 0;
}
