﻿#pragma once

#ifndef PACKET_FEATURE_H
#define PACKET_FEATURE_H

#include <string>

#include <boost/regex.hpp>

#include <Packet.h>


int get_packet_count(const std::string &pcap_path);

std::vector<boost::regex> get_regexes(const std::string &cli_para);

int match_regex_from_reader(bool debug, std::ofstream &fout, const std::string &pcap_path, int packetCount, const std::vector<boost::regex> &pattern_regexes);

#endif // !PACKET_FEATURE_H