/**
 * @file
 *
 * @brief Class encapsulating the executable being dissassembled.
 *
 * @copyright Assemblize is free software: you can redistribute it and/or
 *            modify it under the terms of the GNU General Public License
 *            as published by the Free Software Foundation, either version
 *            3 of the License, or (at your option) any later version.
 *            A full copy of the GNU General Public License can be found in
 *            LICENSE
 */
#include "executable.h"
#include "function.h"
#include <LIEF/LIEF.hpp>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <strings.h>

const char unassemblize::Executable::s_symbolSection[] = "symbols";
const char unassemblize::Executable::s_sectionsSection[] = "sections";
const char unassemblize::Executable::s_configSection[] = "config";
const char unassemblize::Executable::s_objectSection[] = "objects";

unassemblize::Executable::Executable(const char *file_name, OutputFormats format, bool verbose) :
    m_binary(LIEF::Parser::parse(file_name)),
    m_endAddress(0),
    m_outputFormat(format),
    m_codeAlignment(sizeof(uint32_t)),
    m_dataAlignment(sizeof(uint32_t)),
    m_codePad(0x90), // NOP
    m_dataPad(0x00),
    m_verbose(verbose)
{
    if (m_verbose) {
        printf("Loading section info...\n");
    }

    for (auto it = m_binary->sections().begin(); it != m_binary->sections().end(); ++it) {
        if (!it->name().empty() && it->size() != 0) {
            SectionInfo &section = m_sections[it->name()];
            section.data = it->content().data();

            // For PE format virtual_address appears to be an offset, in ELF/Mach-O it appears to be absolute.
            if (it->virtual_address() > m_binary->imagebase()) {
                section.address = it->virtual_address();
            } else {
                section.address = m_binary->imagebase() + it->virtual_address();
            }

            section.size = it->size();

            if (section.address + section.size > m_endAddress) {
                m_endAddress = section.address + section.size;
            }

            // Naive split on whether section contains data or code... have entrypoint? Code, else data.
            // Needs to be refined by providing a config file with section types specified.
            if (section.address <= m_binary->entrypoint() && section.address + section.size >= m_binary->entrypoint()) {
                section.type = SECTION_CODE;
            } else {
                section.type = SECTION_DATA;
            }
        }
    }

    if (m_verbose) {
        printf("Indexing embedded symbols...\n");
    }

    auto exe_syms = m_binary->symbols();

    for (auto it = exe_syms.begin(); it != exe_syms.end(); ++it) {
        if (it->value() != 0 && !it->name().empty() && m_symbolMap.find(it->value()) == m_symbolMap.end()) {
            m_symbolMap.insert({it->value(), Symbol(it->name(), it->value(), it->size())});
        }
    }

    auto exe_imports = m_binary->imported_functions();

    for (auto it = exe_imports.begin(); it != exe_imports.end(); ++it) {
        if (it->value() != 0 && !it->name().empty() && m_symbolMap.find(it->value()) == m_symbolMap.end()) {
            m_loadedSymbols.push_back(it->name());
            m_symbolMap.insert({it->value(), Symbol(m_loadedSymbols.back(), it->value(), it->size())});
        }
    }
}

const uint8_t *unassemblize::Executable::section_data(const char *name) const
{
    auto it = m_sections.find(name);
    return it != m_sections.end() ? it->second.data : nullptr;
}

uint64_t unassemblize::Executable::section_address(const char *name) const
{
    auto it = m_sections.find(name);
    return it != m_sections.end() ? it->second.address : UINT64_MAX;
}

uint64_t unassemblize::Executable::section_size(const char *name) const
{
    auto it = m_sections.find(name);
    return it != m_sections.end() ? it->second.size : 0;
}

uint64_t unassemblize::Executable::base_address() const
{
    return m_binary->imagebase();
}

const unassemblize::Executable::Symbol &unassemblize::Executable::get_symbol(uint64_t addr) const
{
    static std::string empty;
    static Symbol def(empty, 0, 0);
    auto it = m_symbolMap.find(addr);

    if (it != m_symbolMap.end()) {
        return it->second;
    }

    return def;
}

const unassemblize::Executable::Symbol &unassemblize::Executable::get_nearest_symbol(uint64_t addr) const
{
    static std::string empty;
    static Symbol def(empty, 0, 0);
    auto it = m_symbolMap.lower_bound(addr);

    if (it != m_symbolMap.end()) {
        if (it->second.value == addr) {
            return it->second;
        } else {
            return std::prev(it)->second;
        }
    }

    return def;
}

void unassemblize::Executable::add_symbol(const char *sym, uint64_t addr)
{
    if (m_symbolMap.find(addr) == m_symbolMap.end()) {
        m_loadedSymbols.push_back(sym);
        m_symbolMap.insert({addr, Symbol(m_loadedSymbols.back(), addr, 0)});
    }
}

void unassemblize::Executable::load_config(const char *file_name)
{
    if (m_verbose) {
        printf("Loading config file '%s'...\n", file_name);
    }

    std::ifstream fs(file_name);

    if (!fs.good()) {
        return;
    }

    nlohmann::json j = nlohmann::json::parse(fs);

    if (j.find(s_configSection) != j.end()) {
        nlohmann::json &conf = j.at(s_configSection);
        conf.at("codealign").get_to(m_codeAlignment);
        conf.at("dataalign").get_to(m_dataAlignment);
        conf.at("codepadding").get_to(m_codePad);
        conf.at("datapadding").get_to(m_dataPad);
    }

    if (j.find(s_symbolSection) != j.end()) {
        load_symbols(j.at(s_symbolSection));
    }

    if (j.find(s_sectionsSection) != j.end()) {
        load_sections(j.at(s_sectionsSection));
    }

    if (j.find(s_objectSection) != j.end()) {
        load_objects(j.at(s_objectSection));
    }
}

void unassemblize::Executable::save_config(const char *file_name)
{
    if (m_verbose) {
        printf("Saving config file '%s'...\n", file_name);
    }

    nlohmann::json j;

    // Parse the config file if it already exists and update it.
    {
        std::ifstream fs(file_name);

        if (fs.good()) {
            j = nlohmann::json::parse(fs);
        }
    }

    if (j.find(s_configSection) == j.end()) {
        j[s_configSection] = nlohmann::json();
    }

    nlohmann::json &conf = j.at(s_configSection);
    conf["codealign"] = m_codeAlignment;
    conf["dataalign"] = m_dataAlignment;
    conf["codepadding"] = m_codePad;
    conf["datapadding"] = m_dataPad;

    // Don't dump if we already have a sections for these.
    if (j.find(s_symbolSection) == j.end()) {
        j[s_symbolSection] = nlohmann::json();
        dump_symbols(j.at(s_symbolSection));
    }

    if (j.find(s_sectionsSection) == j.end()) {
        j[s_sectionsSection] = nlohmann::json();
        dump_sections(j.at(s_sectionsSection));
    }

    if (j.find(s_objectSection) == j.end()) {
        j[s_objectSection] = nlohmann::json();
        dump_objects(j.at(s_objectSection));
    }

    std::ofstream fs(file_name);
    fs << std::setw(4) << j << std::endl;
}

void unassemblize::Executable::load_symbols(nlohmann::json &js)
{
    if (m_verbose) {
        printf("Loading external symbols...\n");
    }

    for (auto it = js.begin(); it != js.end(); ++it) {
        std::string name;
        it->at("name").get_to(name);

        // Don't try and load an empty symbol.
        if (!name.empty()) {
            uint64_t size = 0;
            uint64_t addr = 0;
            it->at("address").get_to(addr);

            if (addr == 0) {
                continue;
            }

            it->at("size").get_to(size);

            if (size == 0) {
                continue;
            }

            // Only load symbols for addresses we don't have any symbol for yet.
            if (m_symbolMap.find(addr) == m_symbolMap.end()) {
                m_loadedSymbols.push_back(name);
                m_symbolMap.insert({addr, {m_loadedSymbols.back(), addr, size}});
            }
        }
    }
}

void unassemblize::Executable::dump_symbols(nlohmann::json &js)
{
    if (m_verbose) {
        printf("Saving symbols...\n");
    }

    for (auto it = m_symbolMap.begin(); it != m_symbolMap.end(); ++it) {
        js.push_back({{"name", it->second.name}, {"address", it->second.value}, {"size", it->second.size}});
    }
}

void unassemblize::Executable::load_sections(nlohmann::json &js)
{
    if (m_verbose) {
        printf("Loading section info...\n");
    }

    for (auto it = js.begin(); it != js.end(); ++it) {
        std::string name;
        it->at("name").get_to(name);

        // Don't try and load an empty symbol.
        if (!name.empty()) {
            auto section = m_sections.find(name);

            if (section == m_sections.end() && m_verbose) {
                printf("Tried to load section info for section not present in this binary!\n");
                printf("Section '%s' info was ignored.\n", name.c_str());
            }

            std::string type;
            it->at("type").get_to(type);

            if (strcasecmp(type.c_str(), "code") == 0) {
                section->second.type = SECTION_CODE;
            } else if (strcasecmp(type.c_str(), "data") == 0) {
                section->second.type = SECTION_DATA;
            } else if (m_verbose) {
                printf("Incorrect type specified for section '%s'.\n", name.c_str());
            }
        }
    }
}

void unassemblize::Executable::dump_sections(nlohmann::json &js)
{
    if (m_verbose) {
        printf("Saving section info...\n");
    }

    for (auto it = m_sections.begin(); it != m_sections.end(); ++it) {
        js.push_back({{"name", it->first}, {"type", it->second.type == SECTION_CODE ? "code" : "data"}});
    }
}

void unassemblize::Executable::load_objects(nlohmann::json &js)
{
    if (m_verbose) {
        printf("Loading objects...\n");
    }

    for (auto it = js.begin(); it != js.end(); ++it) {
        std::string obj_name;
        it->at("name").get_to(obj_name);

        if (obj_name.empty()) {
            continue;
        }

        m_targetObjects.push_back({obj_name, std::list<ObjectSection>()});
        auto &obj = m_targetObjects.back();
        auto &sections = js.back().at("sections");

        for (auto sec = sections.begin(); sec != sections.end(); ++sec) {
            std::string name;
            uint64_t start;
            uint64_t size;
            sec->at("name").get_to(name);
            sec->at("start").get_to(start);
            sec->at("size").get_to(size);
            obj.sections.push_back({name, start, size});
        }
    }
}

void unassemblize::Executable::dump_objects(nlohmann::json &js)
{
    if (m_verbose) {
        printf("Saving objects...\n");
    }

    if (m_targetObjects.empty()) {
        m_targetObjects.push_back(
            {m_binary->name().substr(m_binary->name().find_last_of("/\\") + 1), std::list<ObjectSection>()});
        auto &obj = m_targetObjects.back();

        for (auto it = m_binary->sections().begin(); it != m_binary->sections().end(); ++it) {
            if (it->name().empty() || it->size() == 0) {
                continue;
            }

            obj.sections.push_back({it->name(), 0, it->size()});
        }
    }

    for (auto it = m_targetObjects.begin(); it != m_targetObjects.end(); ++it) {        
        js.push_back({{"name", it->name}, {"sections", nlohmann::json()}});
        auto &sections = js.back().at("sections");

        for (auto it2 = it->sections.begin(); it2 != it->sections.end(); ++it2) {
            sections.push_back({{"name", it2->name}, {"start", it2->start}, {"size", it2->size}});
        }
    }
}

void unassemblize::Executable::dissassemble_function(
    FILE *output, const char *section_name, uint64_t start, uint64_t end)
{
    // Abort if we can't output anywhere.
    if (output == nullptr) {
        return;
    }

    if (m_outputFormat != OUTPUT_MASM) {
        dissassemble_gas_func(output, section_name, start, end);
    }
}

void unassemblize::Executable::dissassemble_gas_func(
    FILE *output, const char *section_name, uint64_t start, uint64_t end)
{
    if (start != 0 && end != 0) {
        unassemblize::Function func(*this, section_name, start, end);
        if (m_outputFormat == OUTPUT_IGAS) {
            func.disassemble(Function::FORMAT_IGAS);
        } else {
            func.disassemble(Function::FORMAT_AGAS);
        }

        const std::string &sym = get_symbol(start).name;

        if (!sym.empty()) {
            fprintf(output,
                ".globl %s\n%s:\n%s",
                sym.c_str(),
                sym.c_str(),
                func.dissassembly().c_str());
        } else {
            fprintf(output,
                ".globl sub_%" PRIx64 "\nsub_%" PRIx64 ":\n%s",
                start,
                start,
                func.dissassembly().c_str());
        }
    }
}
