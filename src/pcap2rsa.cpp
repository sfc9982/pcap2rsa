#include <iostream>
#include <format>
#include <string>

#include <PcapFileDevice.h>

#include <args.hxx>

#include "packet_feature.h"

#ifdef WIN32
#pragma comment(lib, "Ws2_32.lib")
#endif


/**
 * @brief The entry point of the pcap2rsa program.
 * 
 * This function parses command-line arguments, validates the input, 
 * extracts HTTP parameters from a PCAP/PCAPNG file, and writes the results to an output file.
 * 
 * @param argc The number of command-line arguments.
 * @param argv An array of strings containing the command-line arguments.
 * @return int Returns 0 on success, non-zero on failure.
 */
int main(int argc, char *argv[]) {
    args::ArgumentParser          parser("pcap2rsa - extract parameter of HTTP from PCAP/PCAPNG files", R"(Example: ./pcap2rsa.exe -p rsa,ul,pl "D:/NeFUC/cas.03.17.pcapng" -d)");
    args::HelpFlag                help(parser, "help", "Display this help menu", {'h', "help"});
    args::CompletionFlag          completion(parser, {"complete"});
    args::ValueFlag<std::string>  arg_para(parser, "parameter", "The HTTP parameter to extract", {'p', "parameter"});
    args::Positional<std::string> input_file(parser, "input", "The input pcap(ng) file");
    args::ValueFlag<std::string>  output_file(parser, "output", "The name of output file", {'o', "output"}, "out.txt");
    args::Flag                    debug_mode(parser, "debug", "Display debug information and a progress bar", {'d', "debug"}, args::Options{});

    auto handle_error = [&parser](const std::string &message) {
        std::cerr << message << '\n';
        std::cerr << parser;
        return 1;
    };

    try {
        parser.ParseCLI(argc, argv);
    } catch (const args::Completion &e) {
        std::cout << e.what();
        return 0;
    } catch (const args::Help &) {
        std::cout << parser;
        return 0;
    } catch (const args::ParseError &e) {
        return handle_error(e.what());
    }

    const std::string pcap_path = args::get(input_file);
    if (pcap_path.empty()) {
        return handle_error("Input pcap file path is empty.");
    }

    const std::string output_path = args::get(output_file);
    std::ofstream     fout(output_path);
    if (!fout.is_open()) {
        return handle_error("Failed to open output file.");
    }

    const bool debug = get(debug_mode);
    if (debug) {
        std::cout << "Debug mode: Enabled" << '\n';
        if (arg_para) {
            const std::string parameters = args::get(arg_para);
            std::cout << std::format("Parameter(s): {}", parameters) << '\n';
        }
        std::cout << std::format("Input file: {}", pcap_path) << '\n';
        std::cout << std::format("Output file: {}", output_path) << '\n';
    }

    const int packet_count = get_packet_count(pcap_path);
    if (packet_count == -1) {
        return handle_error("Cannot determine packet count");
    }

    if (debug) {
        std::cout << std::format("Total packets: {}", packet_count) << '\n';
    }

    const std::vector<boost::regex> pattern_regexes = get_regexes(args::get(arg_para));
    const int                       processed_count = match_regex_from_reader(debug, fout, pcap_path, packet_count, pattern_regexes);

    if (debug) {
        std::cout << std::format("Valid HTTP packets: {}", processed_count) << '\n'
                  << std::format("Valid percentage: {:.2f}%",
                                 (static_cast<double>(processed_count) / static_cast<double>(packet_count)) * 100.0f)
                  << '\n';
    }

    return 0;
}