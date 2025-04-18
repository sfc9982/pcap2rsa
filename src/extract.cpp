#include "extract.h"


/**
 * @brief Extract specific strings from a given payload based on a list of regular expressions.
 * 
 * This function iterates through a list of Boost regular expressions and searches for matches within the provided payload.
 * If a match is found and it contains at least one capture group, the content of the first capture group is added to the result vector.
 * 
 * @param payload A string view representing the payload to be searched.
 * @param regexes A vector of Boost regular expressions to apply to the payload.
 * @return std::vector<std::string> A vector containing the extracted strings from the first capture group of each matching regular expression.
 */
std::vector<std::string> extract_payload(const std::string_view &payload, const std::vector<boost::regex> &regexes) {
    std::vector<std::string> extracted;
    extracted.reserve(regexes.size());
    boost::match_results<std::string_view::const_iterator> results;
    for (const auto &pattern : regexes) {
        if (regex_search(payload.begin(), payload.end(), results, pattern)) {
            if (results.size() > 1) {
                extracted.emplace_back(results[1].str());
            }
        }
    }
    return extracted;
}