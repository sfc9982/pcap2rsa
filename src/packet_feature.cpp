#include "packet_feature.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <format>

#include <PcapFileDevice.h>
#include <TcpLayer.h>
#include <HttpLayer.h>

#include "progressbar.hpp"

#include "extract.h"


/**
 * @brief Get the total number of packets in a PCAP file.
 * 
 * This function attempts to open the specified PCAP file and counts the number of packets it contains.
 * If an error occurs during the process, such as failing to determine the reader type or open the file,
 * it prints an error message to the standard error stream and returns -1.
 * 
 * @param pcap_path The path to the PCAP file.
 * @return int The total number of packets in the PCAP file, or -1 if an error occurs.
 */
int get_packet_count(const std::string &pcap_path) {
    pcpp::IFileReaderDevice *size_reader = pcpp::IFileReaderDevice::getReader(pcap_path);

    if (size_reader == nullptr) {
        std::cerr << "Cannot determine reader for file type" << '\n';
        return -1;
    }

    if (!size_reader->open()) {
        std::cerr << std::format("Cannot open {} for reading\n", pcap_path);
        return -1;
    }

    int             packet_count = 0;
    pcpp::RawPacket tmp_packet;
    while (size_reader->getNextPacket(tmp_packet)) {
        packet_count++;
    }

    size_reader->close();
    delete size_reader;

    return packet_count;
}

/**
 * @brief Generate a vector of Boost regular expressions based on the input command-line parameter.
 * 
 * This function takes a command-line parameter string, which can contain one or more comma-separated values.
 * It creates a regular expression for each value, designed to match key-value pairs in a URL query string.
 * 
 * @param cli_para A string containing one or more comma-separated command-line parameters.
 * @return std::vector<boost::regex> A vector of Boost regular expressions generated from the input parameters.
 */
std::vector<boost::regex> get_regexes(const std::string &cli_para) {
    std::vector<boost::regex> pattern_regexes;
    std::stringstream         para_ss(cli_para);
    if (cli_para.find(',') != std::string::npos) { // check if multiple parameters are provided
        std::string single_parameter;
        while (std::getline(para_ss, single_parameter, ',')) {
            pattern_regexes.emplace_back(std::format("{}=([^&]+)", single_parameter));
        }
    } else {
        pattern_regexes.emplace_back(std::format("{}=([^&]+)", cli_para));
    }

    return pattern_regexes;
}

/**
 * @brief Match regular expressions from a PCAP file reader and write the results to an output file.
 * 
 * This function reads packets from a PCAP file, filters TCP packets sent to port 80 with HTTP requests,
 * extracts payloads from these packets, and matches them against a list of regular expressions.
 * The matched results are written to the output file.
 * 
 * @param debug A boolean flag indicating whether to show the progress bar.
 * @param fout An output file stream to write the matched results.
 * @param pcap_path The path to the PCAP file to read.
 * @param packetCount The total number of packets in the PCAP file.
 * @param pattern_regexes A vector of Boost regular expressions to match against the packet payloads.
 * @return int The number of packets processed.
 */
int match_regex_from_reader(const bool debug, std::ofstream &fout, const std::string &pcap_path, const int packetCount, const std::vector<boost::regex> &pattern_regexes) {
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(pcap_path);
    reader->open();

    int         idx  = 0;
    int         proc = 0;
    progressbar pb(100);
    pb.show_bar(debug);

    pcpp::RawPacket raw_packet;
    while (reader->getNextPacket(raw_packet)) {
        if (debug) {
            // update progress bar every 1% of the total num of packets have been processed,
            // 100 is ratio which must equal to value in progressbar variable definition above.
            if (++idx % (packetCount / 100) == 0) {
                pb.update();
            }
        }

        pcpp::Packet parsed_packet(&raw_packet);

        if (!parsed_packet.isPacketOfType(pcpp::TCP)) {
            continue;
        }

        if (const pcpp::TcpLayer *tcp_layer = parsed_packet.getLayerOfType<pcpp::TcpLayer>();
            tcp_layer->getDstPort() != 80) {
            continue;
        }

        if (!parsed_packet.isPacketOfType(pcpp::HTTPRequest)) {
            continue;
        }

        const pcpp::HttpRequestLayer *http_layer = parsed_packet.getLayerOfType<pcpp::HttpRequestLayer>();

        if (http_layer->getProtocol() != pcpp::HTTPRequest) {
            continue;
        }

        const auto   payload_ptr  = reinterpret_cast<std::string_view::const_pointer>(http_layer->getLayerPayload());
        const size_t payload_size = http_layer->getLayerPayloadSize();

        if (payload_ptr == nullptr || payload_size <= 0) {
            continue;
        }

        proc++;

        const std::string_view   payload(payload_ptr, payload_size);
        std::vector<std::string> para_list = extract_payload(payload, pattern_regexes);

        if (!para_list.empty()) {
            for (const auto &p : para_list) {
                fout << p;
                if (&p != &para_list.back()) {
                    fout << ',';
                }
            }
            fout << '\n';
        }
    }

    if (debug) {
        std::cout << '\n';
    }

    reader->close();
    delete reader;

    return proc;
}